#include "http_server.h"
#include "esp_log.h"
#include "wifi_mgr.h"
#include "config_store.h"
#include "driver/gpio.h"
#include "cJSON.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "ble_hid.h"
#include "uart_bridge.h"
#include <cstdio>
#include <string>
#include <vector>
#include <atomic>
#include <cstdint>
#include <algorithm>
#include <cstring>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "nimble/ble.h"

extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[]   asm("_binary_index_html_end");

static const char* TAG = "http";
static httpd_handle_t s_server = nullptr;
// When true, handlers should avoid attempting socket IO because server is shutting down
static volatile bool s_http_shutting_down = false;
// Count of active request handlers (incremented at handler entry, decremented at exit)
static std::atomic<int> s_http_active_handlers{0};
// number of websocket clients currently connected
static std::atomic<int> s_ws_clients{0};

namespace {
static constexpr const char kHttpStatusPayloadTooLarge[] = "413 Payload Too Large";

enum class configure_state : uint8_t {
    Idle = 0,
    Pending,
    Success,
    Failed
};

struct configure_status_t {
    configure_state state = configure_state::Idle;
    std::string message;
    std::string sta_ip;
    std::string sta_url;
    uint32_t version = 0;
};

static SemaphoreHandle_t s_cfg_mutex = nullptr;
static configure_status_t s_cfg_status;

static std::string format_mac(const uint8_t mac[6]){
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

static const char* ble_addr_type_label(uint8_t type){
    switch (type){
    case BLE_ADDR_PUBLIC: return "public";
    case BLE_ADDR_RANDOM: return "random";
    case BLE_ADDR_PUBLIC_ID: return "public_id";
    case BLE_ADDR_RANDOM_ID: return "random_id";
    default: return "unknown";
    }
}

static std::string format_ble_addr(const uint8_t addr[6]){
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return std::string(buf);
}

static std::string format_ble_hex(const uint8_t addr[6]){
    char buf[13];
    snprintf(buf, sizeof(buf), "%02X%02X%02X%02X%02X%02X",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return std::string(buf);
}

static std::string make_peer_id(uint8_t type, const uint8_t addr[6]){
    std::string id = ble_addr_type_label(type);
    id.push_back('-');
    id += format_ble_hex(addr);
    return id;
}

static std::string request_url(httpd_req_t* req){
    if (!req) {
        return std::string();
    }

    std::string target(req->uri);
    size_t query_len = httpd_req_get_url_query_len(req);
    if (query_len > 0) {
        std::vector<char> query(query_len + 1, 0);
        esp_err_t err = httpd_req_get_url_query_str(req, query.data(), query.size());
        if (err == ESP_OK && query[0] != '\0') {
            target.push_back('?');
            target.append(query.data());
        } else if (err != ESP_OK) {
            ESP_LOGW(TAG, "request_url: httpd_req_get_url_query_str -> %d", err);
        }
    }
    return target;
}

static int hex_value(char c){
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static bool parse_peer_id(const std::string& id, uint8_t& out_type, uint8_t out_addr[6]){
    auto dash = id.find('-');
    if (dash == std::string::npos) return false;
    std::string type_str = id.substr(0, dash);
    std::string hex = id.substr(dash + 1);
    if (hex.size() != 12) return false;

    if (type_str == "public") out_type = BLE_ADDR_PUBLIC;
    else if (type_str == "random") out_type = BLE_ADDR_RANDOM;
    else if (type_str == "public_id") out_type = BLE_ADDR_PUBLIC_ID;
    else if (type_str == "random_id") out_type = BLE_ADDR_RANDOM_ID;
    else return false;

    for (size_t i = 0; i < 6; ++i){
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out_addr[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static std::string get_hostname(){
    const char* hostname = "";
    esp_netif_t* netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!netif){
        netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    }
    if (netif){
        const char* hn = nullptr;
        if (esp_netif_get_hostname(netif, &hn) == ESP_OK && hn){
            hostname = hn;
        }
    }
    return std::string(hostname ? hostname : "");
}

static void cfg_status_ensure_mutex(){
    if (!s_cfg_mutex){
        s_cfg_mutex = xSemaphoreCreateMutex();
    }
}

static void cfg_status_set(configure_state state, const std::string& message,
                           const std::string& sta_ip, const std::string& sta_url){
    cfg_status_ensure_mutex();
    if (!s_cfg_mutex) return;
    xSemaphoreTake(s_cfg_mutex, portMAX_DELAY);
    s_cfg_status.state = state;
    s_cfg_status.message = message;
    s_cfg_status.sta_ip = sta_ip;
    s_cfg_status.sta_url = sta_url;
    s_cfg_status.version++;
    xSemaphoreGive(s_cfg_mutex);
}

static configure_status_t cfg_status_get(){
    configure_status_t snapshot;
    cfg_status_ensure_mutex();
    if (!s_cfg_mutex) return snapshot;
    xSemaphoreTake(s_cfg_mutex, portMAX_DELAY);
    snapshot = s_cfg_status;
    xSemaphoreGive(s_cfg_mutex);
    return snapshot;
}
} // namespace

static void ws_client_dec(){
    int prev = s_ws_clients.fetch_sub(1);
    if (prev <= 0){
        s_ws_clients.store(0);
    }
}

// RAII guard to track active handlers
struct HandlerGuard {
    HandlerGuard() { s_http_active_handlers.fetch_add(1); }
    ~HandlerGuard() { s_http_active_handlers.fetch_sub(1); }
};

static esp_err_t send_status_with_body(httpd_req_t* req, const char* status, const char* body) {
    if (!req) {
        return ESP_FAIL;
    }
    httpd_resp_set_status(req, status ? status : "200 OK");
    httpd_resp_set_type(req, "text/plain");
    const char* payload = body ? body : "";
    esp_err_t ret = httpd_resp_sendstr(req, payload);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "send_status_with_body: httpd_resp_sendstr -> %d", ret);
    }
    return ret;
}

static esp_err_t root_get(httpd_req_t* req){
    HandlerGuard _hg;
    if (s_http_shutting_down) return ESP_FAIL;
    const char* ct = "text/html";
    httpd_resp_set_type(req, ct);
    size_t len = index_html_end - index_html_start;
    esp_err_t ret = httpd_resp_send(req, (const char*)index_html_start, len);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "root_get: httpd_resp_send -> %d", ret);
    }
    return ret;
}

static esp_err_t scan_get(httpd_req_t* req){
    HandlerGuard _hg;
    if (s_http_shutting_down) return ESP_FAIL;
    // legacy: perform an immediate scan (blocking). Prefer using start/stop + /scan/results
    auto nets = wifi_scan();
    cJSON* arr = cJSON_CreateArray();
    for (auto& n : nets){
        cJSON* o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "ssid", n.ssid.c_str());
        cJSON_AddNumberToObject(o, "rssi", n.rssi);
        cJSON_AddItemToArray(arr, o);
    }
    char* json = cJSON_PrintUnformatted(arr);
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "scan_get: httpd_resp_sendstr -> %d", ret);
    }
    cJSON_free(json);
    cJSON_Delete(arr);
    return ret;
}

static esp_err_t scan_results_get(httpd_req_t* req){
    HandlerGuard _hg;
    if (s_http_shutting_down) return ESP_FAIL;
    ESP_LOGI(TAG, "scan_results_get: request from %p", req);
    auto nets = wifi_get_last_scan();
    cJSON* arr = cJSON_CreateArray();
    for (auto& n : nets){
        cJSON* o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "ssid", n.ssid.c_str());
        cJSON_AddNumberToObject(o, "rssi", n.rssi);
        cJSON_AddItemToArray(arr, o);
    }
    char* json = cJSON_PrintUnformatted(arr);
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "scan_results_get: httpd_resp_sendstr -> %d", ret);
    }
    cJSON_free(json);
    cJSON_Delete(arr);
    return ret;
}

static esp_err_t scan_start_post(httpd_req_t* req){
    HandlerGuard _hg;
    if (s_http_shutting_down) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "shutting down");
    ESP_LOGI(TAG, "scan_start_post: request from %p", req);
    wifi_scan_start();
    cJSON* o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "scan_active", wifi_scan_is_active());
    char* json = cJSON_PrintUnformatted(o);
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    cJSON_free(json);
    cJSON_Delete(o);
    return ret;
}

static esp_err_t scan_stop_post(httpd_req_t* req){
    HandlerGuard _hg;
    if (s_http_shutting_down) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "shutting down");
    ESP_LOGI(TAG, "scan_stop_post: request from %p", req);
    wifi_scan_stop();
    cJSON* o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "scan_active", wifi_scan_is_active());
    char* json = cJSON_PrintUnformatted(o);
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    cJSON_free(json);
    cJSON_Delete(o);
    return ret;
}

static esp_err_t status_get(httpd_req_t* req){
    HandlerGuard _hg;
    if (s_http_shutting_down) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "shutting down");
    ESP_LOGI(TAG, "status_get: request from %p", req);
    cJSON* o = cJSON_CreateObject();
    // Status JSON fields exposed to the web dashboard:
    //   wifi_enabled / uart_enabled / web_enabled : persisted toggle states.
    //   hostname : string from esp_netif_get_hostname (STA preferred, AP fallback).
    //   sta : object with { ip, mac, ssid, connected }.
    //   ap : object with { ip, mac, client_count, clients[] (mac, rssi) }.
    //   scan_active : background Wi-Fi scan running flag (legacy top-level preserved).
    //   ws_clients : number of websocket clients currently attached.
    //   configure : provisioning progress mirror (state/message/sta_ip/version).
    //   bonded_count : number of bonded BLE peers.
    //   ble_connected : true when a BLE Central is connected to the HID service.
    //   uart_seen_data : UART bridge observed input since boot.
    // add persisted toggles and websocket client count
    bridge_toggles_t toggles = cfg_load_toggles();
    cJSON_AddBoolToObject(o, "wifi_enabled", toggles.enable_wifi);
    std::string sta_ip;
    std::string ap_ip;
    std::string connected_ssid;
    bool scan_active = false;
    if (toggles.enable_wifi) {
        sta_ip = wifi_get_sta_ip();
        ap_ip = wifi_get_ap_ip();
        connected_ssid = wifi_get_connected_ssid();
        scan_active = wifi_scan_is_active();
    }
    std::string sta_url = sta_ip.empty() ? std::string() : "http://" + sta_ip;
    cJSON_AddStringToObject(o, "sta_ip", sta_ip.c_str());
    cJSON_AddStringToObject(o, "sta_url", sta_url.c_str());
    cJSON_AddStringToObject(o, "ap_ip", ap_ip.c_str());
    cJSON_AddStringToObject(o, "connected_ssid", connected_ssid.c_str());
    cJSON_AddBoolToObject(o, "scan_active", scan_active);
    std::string hostname = get_hostname();
    cJSON_AddStringToObject(o, "hostname", hostname.c_str());
    char last_ssid[33] = {0};
    cfg_get_last_ssid(last_ssid, sizeof(last_ssid));
    cJSON_AddStringToObject(o, "last_ssid", last_ssid);
    uint8_t sta_mac_raw[6] = {0};
    std::string sta_mac;
    if (esp_wifi_get_mac(WIFI_IF_STA, sta_mac_raw) == ESP_OK) {
        sta_mac = format_mac(sta_mac_raw);
    }
    cJSON_AddStringToObject(o, "sta_mac", sta_mac.c_str());
    uint8_t ap_mac_raw[6] = {0};
    std::string ap_mac;
    if (esp_wifi_get_mac(WIFI_IF_AP, ap_mac_raw) == ESP_OK) {
        ap_mac = format_mac(ap_mac_raw);
    }
    cJSON_AddStringToObject(o, "ap_mac", ap_mac.c_str());
    cJSON* sta_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(sta_obj, "ip", sta_ip.c_str());
    cJSON_AddStringToObject(sta_obj, "url", sta_url.c_str());
    cJSON_AddStringToObject(sta_obj, "mac", sta_mac.c_str());
    cJSON_AddStringToObject(sta_obj, "ssid", connected_ssid.c_str());
    cJSON_AddBoolToObject(sta_obj, "connected", !sta_ip.empty());
    cJSON_AddItemToObject(o, "sta", sta_obj);
    cJSON* ap_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(ap_obj, "ip", ap_ip.c_str());
    cJSON_AddStringToObject(ap_obj, "mac", ap_mac.c_str());
    int client_count = 0;
    std::vector<ap_client_info_t> ap_clients = wifi_get_ap_clients(&client_count);
    cJSON_AddNumberToObject(ap_obj, "client_count", client_count);
    cJSON* clients = cJSON_CreateArray();
    for (const auto& client : ap_clients) {
        cJSON* entry = cJSON_CreateObject();
        std::string client_mac = format_mac(client.mac.data());
        cJSON_AddStringToObject(entry, "mac", client_mac.c_str());
        cJSON_AddNumberToObject(entry, "rssi", client.rssi);
        if (client.has_ip) {
            esp_ip4_addr_t ip;
            ip.addr = client.ip;
            char ip_buf[16] = {0};
            esp_ip4addr_ntoa(&ip, ip_buf, sizeof(ip_buf));
            cJSON_AddStringToObject(entry, "ip", ip_buf);
        } else {
            cJSON_AddStringToObject(entry, "ip", "");
        }
        cJSON_AddItemToArray(clients, entry);
    }
    cJSON_AddItemToObject(ap_obj, "clients", clients);
    cJSON_AddItemToObject(o, "ap", ap_obj);
    cJSON_AddBoolToObject(o, "uart_enabled", toggles.enable_uart);
    cJSON_AddBoolToObject(o, "web_enabled", toggles.enable_web);
    cJSON_AddNumberToObject(o, "ws_clients", s_ws_clients.load());
    {
        configure_status_t cfg = cfg_status_get();
        cJSON* cfg_obj = cJSON_CreateObject();
        const char* state_str = "idle";
        switch (cfg.state) {
            case configure_state::Pending: state_str = "pending"; break;
            case configure_state::Success: state_str = "success"; break;
            case configure_state::Failed:  state_str = "failed";  break;
            case configure_state::Idle:    default: break;
        }
        cJSON_AddStringToObject(cfg_obj, "state", state_str);
        cJSON_AddStringToObject(cfg_obj, "message", cfg.message.c_str());
        cJSON_AddStringToObject(cfg_obj, "sta_ip", cfg.sta_ip.c_str());
        cJSON_AddStringToObject(cfg_obj, "sta_url", cfg.sta_url.c_str());
        cJSON_AddNumberToObject(cfg_obj, "version", cfg.version);
        cJSON_AddItemToObject(o, "configure", cfg_obj);
    }
    // Include bonded peer count if available
    int bonded = ble_hid_get_bonded_count();
    cJSON_AddNumberToObject(o, "bonded_count", bonded);
    cJSON_AddBoolToObject(o, "ble_connected", ble_hid_is_connected());
    cJSON_AddBoolToObject(o, "uart_seen_data", uart_bridge_has_seen_data());
    char* json = cJSON_PrintUnformatted(o);
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "status_get: httpd_resp_sendstr -> %d", ret);
    }
    cJSON_free(json);
    cJSON_Delete(o);
    return ret;
}

// ----- BLE peers: bonded count and forget-all -----
static esp_err_t ble_peers_get(httpd_req_t* req){
    HandlerGuard _hg;
    if (s_http_shutting_down) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "shutting down");
    int bonded_estimate = ble_hid_get_bonded_count();
    std::vector<ble_hid_peer_info_t> peers;
    size_t total = 0;
    if (bonded_estimate > 0){
        peers.resize(static_cast<size_t>(bonded_estimate));
        total = ble_hid_get_bonded_peers(peers.empty() ? nullptr : peers.data(), peers.size());
        if (total > peers.size()){
            peers.resize(total);
            if (!peers.empty()){
                total = ble_hid_get_bonded_peers(peers.data(), peers.size());
            }
        }
    }
    size_t used = std::min(total, peers.size());

    cJSON* root = cJSON_CreateObject();
    cJSON* arr = cJSON_CreateArray();
    for (size_t i = 0; i < used; ++i){
        const ble_hid_peer_info_t& peer = peers[i];
        cJSON* item = cJSON_CreateObject();
        std::string addr_str = format_ble_addr(peer.addr);
        std::string type_str = ble_addr_type_label(peer.addr_type);
        std::string id = make_peer_id(peer.addr_type, peer.addr);
        cJSON_AddStringToObject(item, "addr", addr_str.c_str());
        cJSON_AddStringToObject(item, "addr_type", type_str.c_str());
        cJSON_AddStringToObject(item, "id", id.c_str());
        cJSON_AddStringToObject(item, "name", peer.name[0] ? peer.name : "");
        cJSON_AddBoolToObject(item, "connected", peer.connected);
        cJSON_AddItemToArray(arr, item);
    }
    cJSON_AddItemToObject(root, "peers", arr);
    cJSON_AddNumberToObject(root, "bonded_count", static_cast<double>(total));
    char* json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "ble_peers_get: httpd_resp_sendstr -> %d", ret);
    }
    cJSON_free(json);
    cJSON_Delete(root);
    return ret;
}

static esp_err_t ble_peers_forget_post(httpd_req_t* req){
    HandlerGuard _hg;
    if (s_http_shutting_down) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "shutting down");
    ESP_LOGI(TAG, "ble_peers_forget_post: request from %p", req);
    int before = ble_hid_get_bonded_count();
    int rc = ble_hid_clear_bonded_peers();
    int after = ble_hid_get_bonded_count();
    cJSON* o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "before", before);
    cJSON_AddNumberToObject(o, "after", after);
    cJSON_AddNumberToObject(o, "rc", rc);
    char* json = cJSON_PrintUnformatted(o);
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "ble_peers_forget_post: httpd_resp_sendstr -> %d", ret);
    }
    cJSON_free(json);
    cJSON_Delete(o);
    return ret;
}

static esp_err_t ble_peer_delete(httpd_req_t* req){
    HandlerGuard _hg;
    if (s_http_shutting_down) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "shutting down");
    std::string target = request_url(req);
    if (target.empty()) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid url");
    }
    const std::string prefix = "/ble/peers/";
    if (target.compare(0, prefix.size(), prefix) != 0) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid url");
    }
    std::string id = target.substr(prefix.size());
    auto query_pos = id.find('?');
    if (query_pos != std::string::npos) {
        id.resize(query_pos);
    }
    if (id.empty()){
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing addr");
    }
    uint8_t addr_type = 0;
    uint8_t addr[6] = {0};
    if (!parse_peer_id(id, addr_type, addr)){
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid addr");
    }
    ESP_LOGI(TAG, "ble_peer_delete: id=%s", id.c_str());
    if (!ble_hid_forget_peer(addr_type, addr)){
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "delete failed");
    }
    int bonded = ble_hid_get_bonded_count();
    cJSON* o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "id", id.c_str());
    cJSON_AddBoolToObject(o, "deleted", true);
    cJSON_AddNumberToObject(o, "bonded_count", bonded);
    char* json = cJSON_PrintUnformatted(o);
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "ble_peer_delete: httpd_resp_sendstr -> %d", ret);
    }
    cJSON_free(json);
    cJSON_Delete(o);
    return ret;
}

static esp_err_t configure_post(httpd_req_t* req){
    HandlerGuard _hg;
    if (s_http_shutting_down) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "shutting down");
    static constexpr size_t kMaxConfigureBody = 4096;
    size_t content_length = req->content_len;
    if (content_length == 0) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty body");
    }
    if (content_length > kMaxConfigureBody) {
        ESP_LOGW(TAG, "configure_post: body too large (%zu)", content_length);
        return send_status_with_body(req, kHttpStatusPayloadTooLarge, "body too large");
    }

    std::vector<char> body(content_length + 1, 0);
    size_t received_total = 0;
    while (received_total < content_length) {
        int r = httpd_req_recv(req, body.data() + received_total, content_length - received_total);
        if (r < 0) {
            if (r == HTTPD_SOCK_ERR_TIMEOUT) {
                continue;
            }
            ESP_LOGW(TAG, "configure_post: httpd_req_recv -> %d", r);
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
        }
        received_total += static_cast<size_t>(r);
    }
    if (received_total != content_length) {
        ESP_LOGW(TAG, "configure_post: short body (%zu/%zu)", received_total, content_length);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    }
    body[received_total] = 0;
    cJSON* root = cJSON_Parse(body.data());
    if (!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad json");
    const char* ssid = cJSON_GetStringValue(cJSON_GetObjectItem(root, "ssid"));
    const char* pw   = cJSON_GetStringValue(cJSON_GetObjectItem(root, "password"));
    if (!ssid || !*ssid){
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID required");
    }

    // Copy values for the background task
    std::string ssid_copy(ssid);
    std::string pw_copy(pw ? pw : "");

    // Update configure status immediately so clients can show progress.
    std::string pending_msg = "Connecting to '" + ssid_copy + "'…";
    cfg_status_set(configure_state::Pending, pending_msg, "", "");

    // Background task will perform the connect and post actions
    struct cfg_task_arg { std::string ssid; std::string pw; };
    cfg_task_arg* arg = new cfg_task_arg{ssid_copy, pw_copy};
    auto cfg_task = [](void* pv) -> void {
        cfg_task_arg* a = (cfg_task_arg*)pv;
        bool ok = wifi_connect(a->ssid.c_str(), a->pw.c_str(), 8);
        if (ok) {
            cfg_set_last_ssid(a->ssid.c_str());
            std::string sta_ip = wifi_get_sta_ip();
            for (int i = 0; i < 20 && sta_ip.empty(); ++i) {
                vTaskDelay(pdMS_TO_TICKS(100));
                sta_ip = wifi_get_sta_ip();
            }
            std::string msg = "Connected to '" + a->ssid + "'";
            if (!sta_ip.empty()) {
                msg += " (" + sta_ip + ")";
            }
            std::string sta_url = sta_ip.empty() ? std::string() : "http://" + sta_ip;
            cfg_status_set(configure_state::Success, msg, sta_ip, sta_url);
            // Allow clients a moment to fetch the success status before shutting down the AP.
            vTaskDelay(pdMS_TO_TICKS(4000));
            if (wifi_is_ap()) wifi_ap_stop();
        }
        else {
            std::string msg = "Failed to connect to '" + a->ssid + "'";
            cfg_status_set(configure_state::Failed, msg, "", "");
        }
        delete a;
        vTaskDelete(NULL);
    };
    // create task with small stack; detach from HTTP handler
    if (xTaskCreate((TaskFunction_t)cfg_task, "cfg_connect", 4096, arg, 5, NULL) != pdPASS) {
        ESP_LOGW(TAG, "configure_post: failed to spawn cfg task");
        cfg_status_set(configure_state::Failed, "Failed to start connect task", "", "");
        delete arg;
    }

    // Return immediate response to the HTTP client; connect result will be async
    httpd_resp_set_type(req, "text/plain");
    esp_err_t tret = httpd_resp_sendstr(req, "OK");
    if (tret != ESP_OK){
        ESP_LOGW(TAG, "configure_post: httpd_resp_sendstr -> %d", tret);
    }
    cJSON_Delete(root);
    return tret;
}

// --- WebSocket echo (/ws) ---
static esp_err_t ws_handler(httpd_req_t *req){
    HandlerGuard _hg;
    if (s_http_shutting_down) return ESP_FAIL;
    if (req->method == HTTP_GET) {
        // websocket handshake completed, count client
        s_ws_clients.fetch_add(1);
        return ESP_OK; // handshake done
    }
    httpd_ws_frame_t ws_pkt = {
        .final = true, .fragmented = false,
        .type = HTTPD_WS_TYPE_TEXT, .payload = NULL, .len = 0
    };
    // Probe the frame length first so we can size the buffer correctly.
    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "ws_handler: httpd_ws_recv_frame(len probe) -> %d", ret);
        ws_client_dec();
        return ret;
    }

    const size_t WS_MAX_FRAME = 4096; // avoid unbounded allocation from remote client
    if (ws_pkt.len > WS_MAX_FRAME) {
        ESP_LOGW(TAG, "ws_handler: rejecting frame len=%zu (> %zu)", (size_t)ws_pkt.len, WS_MAX_FRAME);
        ws_client_dec();
        return ESP_ERR_INVALID_SIZE;
    }

    size_t payload_len = ws_pkt.len;
    ws_pkt.payload = static_cast<uint8_t*>(malloc(payload_len + 1));
    if (!ws_pkt.payload) {
        ESP_LOGW(TAG, "ws_handler: malloc(%zu) failed", payload_len + 1);
        ws_client_dec();
        return ESP_ERR_NO_MEM;
    }

    if (payload_len > 0) {
        ret = httpd_ws_recv_frame(req, &ws_pkt, payload_len);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "ws_handler: httpd_ws_recv_frame(payload) -> %d", ret);
            free(ws_pkt.payload);
            ws_client_dec();
            return ret;
        }
    }

    ws_pkt.payload[payload_len] = '\0';

    bool decremented = false;
    if (ws_pkt.type == HTTPD_WS_TYPE_CLOSE) {
        ws_client_dec();
        decremented = true;
    }

    esp_err_t sret = httpd_ws_send_frame(req, &ws_pkt); // echo
    if (sret != ESP_OK) {
        ESP_LOGW(TAG, "ws_handler: httpd_ws_send_frame -> %d", sret);
        if (!decremented) {
            ws_client_dec();
            decremented = true;
        }
    }

    free(ws_pkt.payload);
    if (ret != ESP_OK && !decremented) {
        ws_client_dec();
    }
    return ret;
}

esp_err_t http_server_start(){
    if (s_server) {
        ESP_LOGI(TAG, "HTTP server already running");
        return ESP_OK;
    }
    s_http_shutting_down = false;

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.stack_size = 8192;
    cfg.server_port = 80;
    cfg.lru_purge_enable = true;
    cfg.uri_match_fn = httpd_uri_match_wildcard;
    cfg.max_uri_handlers = 16;
    if (httpd_start(&s_server, &cfg) != ESP_OK) return ESP_FAIL;
    ESP_LOGI(TAG, "http_server_start: s_server=%p", s_server);

    static httpd_uri_t root_uri; memset(&root_uri, 0, sizeof(root_uri)); root_uri.uri = "/"; root_uri.method = HTTP_GET; root_uri.handler = root_get;
    static httpd_uri_t scan_uri; memset(&scan_uri, 0, sizeof(scan_uri)); scan_uri.uri = "/scan"; scan_uri.method = HTTP_GET; scan_uri.handler = scan_get;
    static httpd_uri_t scan_results_uri; memset(&scan_results_uri, 0, sizeof(scan_results_uri)); scan_results_uri.uri = "/scan/results"; scan_results_uri.method = HTTP_GET; scan_results_uri.handler = scan_results_get;
    static httpd_uri_t scan_start_uri; memset(&scan_start_uri, 0, sizeof(scan_start_uri)); scan_start_uri.uri = "/scan/start"; scan_start_uri.method = HTTP_POST; scan_start_uri.handler = scan_start_post;
    static httpd_uri_t scan_stop_uri; memset(&scan_stop_uri, 0, sizeof(scan_stop_uri)); scan_stop_uri.uri = "/scan/stop"; scan_stop_uri.method = HTTP_POST; scan_stop_uri.handler = scan_stop_post;
    static httpd_uri_t cfg_uri;  memset(&cfg_uri, 0, sizeof(cfg_uri));  cfg_uri.uri  = "/configure"; cfg_uri.method  = HTTP_POST; cfg_uri.handler = configure_post;
    static httpd_uri_t status_uri; memset(&status_uri, 0, sizeof(status_uri)); status_uri.uri = "/status"; status_uri.method = HTTP_GET; status_uri.handler = status_get;
    static httpd_uri_t ble_peers_uri; memset(&ble_peers_uri, 0, sizeof(ble_peers_uri)); ble_peers_uri.uri = "/ble/peers"; ble_peers_uri.method = HTTP_GET; ble_peers_uri.handler = ble_peers_get;
    static httpd_uri_t ble_peers_forget_uri; memset(&ble_peers_forget_uri, 0, sizeof(ble_peers_forget_uri)); ble_peers_forget_uri.uri = "/ble/peers/forget"; ble_peers_forget_uri.method = HTTP_POST; ble_peers_forget_uri.handler = ble_peers_forget_post;
    static httpd_uri_t ble_peer_delete_uri; memset(&ble_peer_delete_uri, 0, sizeof(ble_peer_delete_uri)); ble_peer_delete_uri.uri = "/ble/peers/*"; ble_peer_delete_uri.method = HTTP_DELETE; ble_peer_delete_uri.handler = ble_peer_delete;
    static httpd_uri_t ws_uri;   memset(&ws_uri, 0, sizeof(ws_uri));   ws_uri.uri   = "/ws"; ws_uri.method   = HTTP_GET; ws_uri.handler   = ws_handler; ws_uri.is_websocket = true;

    auto register_uri = [](httpd_handle_t server, httpd_uri_t* uri) {
        esp_err_t err = httpd_register_uri_handler(server, uri);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "http_server_start: httpd_register_uri_handler(%s) -> %d", uri && uri->uri ? uri->uri : "?", err);
        }
        return err;
    };

    register_uri(s_server, &root_uri);
    register_uri(s_server, &scan_uri);
    register_uri(s_server, &scan_results_uri);
    register_uri(s_server, &scan_start_uri);
    register_uri(s_server, &scan_stop_uri);
    register_uri(s_server, &cfg_uri);
    register_uri(s_server, &status_uri);
    register_uri(s_server, &ble_peers_uri);
    register_uri(s_server, &ble_peers_forget_uri);
    register_uri(s_server, &ble_peer_delete_uri);
    register_uri(s_server, &ws_uri);
    ESP_LOGI(TAG, "HTTP server started");
    return ESP_OK;
}

void http_server_stop(){
    if (s_server){
        // signal handlers to avoid socket IO
        s_http_shutting_down = true;
        ESP_LOGI(TAG, "http_server_stop: waiting for handlers to finish before stopping server %p", s_server);
        // give handlers a short window to return
        vTaskDelay(pdMS_TO_TICKS(100));
        // wait for active handlers to drain (timeout after ~2s)
        const int max_wait_ms = 2000;
        int waited = 0;
        while (s_http_active_handlers.load() > 0 && waited < max_wait_ms) {
            ESP_LOGI(TAG, "http_server_stop: waiting, active_handlers=%d", s_http_active_handlers.load());
            vTaskDelay(pdMS_TO_TICKS(50));
            waited += 50;
        }
        ESP_LOGI(TAG, "http_server_stop: stopping server %p (active_handlers=%d)", s_server, s_http_active_handlers.load());
        httpd_stop(s_server);
        s_server = nullptr;
        s_ws_clients.store(0);
        s_http_active_handlers.store(0);
        // give httpd some time to tear down sockets
        vTaskDelay(pdMS_TO_TICKS(50));
        s_http_shutting_down = false;
        ESP_LOGI(TAG, "http_server_stop: stopped");
    }
}

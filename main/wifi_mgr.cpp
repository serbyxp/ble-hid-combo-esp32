#include "wifi_mgr.h"
#include "esp_wifi.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include <string.h>
#include <map>
#include <array>
#include <algorithm>

static const char* TAG = "wifi_mgr";
static EventGroupHandle_t s_wifi_event_group;
static esp_netif_t* s_ap_netif = nullptr;
static esp_netif_t* s_sta_netif = nullptr;
static bool s_ap_running = false;
static bool s_wifi_started = false;
static SemaphoreHandle_t s_state_lock = NULL;
static bool s_sta_connected = false;
static std::string s_last_sta_ip;

struct ap_client_state_t {
    bool has_ip = false;
    uint32_t ip = 0;
};

using mac_key_t = std::array<uint8_t, 6>;
static std::map<mac_key_t, ap_client_state_t> s_ap_client_state;

// scan task state
static volatile bool s_scan_active = false;
static TaskHandle_t s_scan_task = NULL;
static std::vector<scan_result_t> s_last_scan;
static SemaphoreHandle_t s_scan_lock = NULL;

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static void ensure_state_lock(){
    if (!s_state_lock){
        s_state_lock = xSemaphoreCreateMutex();
        if (!s_state_lock){
            ESP_LOGE(TAG, "Failed to create state lock");
        }
    }
}

static mac_key_t mac_to_key(const uint8_t mac[6]){
    mac_key_t key = {};
    if (mac){
        std::copy(mac, mac + 6, key.begin());
    }
    return key;
}

static void event_handler(void* arg, esp_event_base_t event_base,
                          int32_t event_id, void* event_data){
    if (event_base == WIFI_EVENT){
        switch(event_id){
            case WIFI_EVENT_STA_START:
                ESP_LOGI(TAG, "STA start");
                break;
            case WIFI_EVENT_STA_DISCONNECTED:
                if (event_data) {
                    wifi_event_sta_disconnected_t* d = (wifi_event_sta_disconnected_t*)event_data;
                    ESP_LOGI(TAG, "STA disconnected, reason=%d", d->reason);
                } else {
                    ESP_LOGI(TAG, "STA disconnected (no event_data)");
                }
                if (s_state_lock){
                    xSemaphoreTake(s_state_lock, portMAX_DELAY);
                    s_sta_connected = false;
                    s_last_sta_ip.clear();
                    xSemaphoreGive(s_state_lock);
                }
                if (s_wifi_event_group) xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
                break;
            case WIFI_EVENT_AP_START:
                ESP_LOGI(TAG, "AP started");
                s_ap_running = true;
                ensure_state_lock();
                if (s_state_lock){
                    xSemaphoreTake(s_state_lock, portMAX_DELAY);
                    s_ap_client_state.clear();
                    xSemaphoreGive(s_state_lock);
                }
                // Start HTTP server when AP comes up
                extern esp_err_t http_server_start();
                http_server_start();
                break;
            case WIFI_EVENT_AP_STOP: {
                ESP_LOGI(TAG, "AP stopped");
                s_ap_running = false;
                bool sta_connected = false;
                ensure_state_lock();
                if (s_state_lock){
                    xSemaphoreTake(s_state_lock, portMAX_DELAY);
                    sta_connected = s_sta_connected;
                    s_ap_client_state.clear();
                    xSemaphoreGive(s_state_lock);
                }
                if (!sta_connected){
                    // Stop HTTP server only if STA is not keeping the UI alive
                    extern void http_server_stop();
                    http_server_stop();
                } else {
                    ESP_LOGI(TAG, "AP stopped but STA is connected; keeping HTTP server running");
                }
                break;
            }
            case WIFI_EVENT_AP_STACONNECTED:
                if (event_data){
                    wifi_event_ap_staconnected_t* d = (wifi_event_ap_staconnected_t*)event_data;
                    ensure_state_lock();
                    if (s_state_lock){
                        xSemaphoreTake(s_state_lock, portMAX_DELAY);
                        s_ap_client_state[mac_to_key(d->mac)] = ap_client_state_t{};
                        xSemaphoreGive(s_state_lock);
                    }
                }
                break;
            case WIFI_EVENT_AP_STADISCONNECTED:
                if (event_data){
                    wifi_event_ap_stadisconnected_t* d = (wifi_event_ap_stadisconnected_t*)event_data;
                    ensure_state_lock();
                    if (s_state_lock){
                        xSemaphoreTake(s_state_lock, portMAX_DELAY);
                        s_ap_client_state.erase(mac_to_key(d->mac));
                        xSemaphoreGive(s_state_lock);
                    }
                }
                break;
        }
    } else if (event_base == IP_EVENT){
        if (event_id == IP_EVENT_STA_GOT_IP){
            ESP_LOGI(TAG, "STA got IP");
            if (event_data){
                ip_event_got_ip_t* ip = (ip_event_got_ip_t*)event_data;
                char buf[32] = {0};
                esp_ip4addr_ntoa(&ip->ip_info.ip, buf, sizeof(buf));
                ensure_state_lock();
                if (s_state_lock){
                    xSemaphoreTake(s_state_lock, portMAX_DELAY);
                    s_sta_connected = true;
                    s_last_sta_ip = buf;
                    xSemaphoreGive(s_state_lock);
                }
            } else {
                ensure_state_lock();
                if (s_state_lock){
                    xSemaphoreTake(s_state_lock, portMAX_DELAY);
                    s_sta_connected = true;
                    xSemaphoreGive(s_state_lock);
                }
            }
            if (s_wifi_event_group) xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
            // When STA is up, ensure HTTP server is running on the correct interface
            extern esp_err_t http_server_start();
            http_server_start();
        } else if (event_id == IP_EVENT_AP_STAIPASSIGNED){
            if (event_data){
                ip_event_ap_staipassigned_t* ip = (ip_event_ap_staipassigned_t*)event_data;
                ensure_state_lock();
                if (s_state_lock){
                    xSemaphoreTake(s_state_lock, portMAX_DELAY);
                    auto& state = s_ap_client_state[mac_to_key(ip->mac)];
                    state.has_ip = true;
                    state.ip = ip->ip.addr;
                    xSemaphoreGive(s_state_lock);
                }
            }
        }
    }
}

static bool wifi_mark_started(esp_err_t err){
    if (err == ESP_OK || err == ESP_ERR_INVALID_STATE){
        s_wifi_started = true;
        return true;
    }
    return false;
}

static bool wifi_mark_stopped(esp_err_t err){
    if (err == ESP_OK || err == ESP_ERR_WIFI_NOT_INIT || err == ESP_ERR_INVALID_STATE){
        s_wifi_started = false;
        return true;
    }
    return false;
}

void wifi_mgr_init(){
    esp_netif_init();
    esp_event_loop_create_default();

    s_sta_netif = esp_netif_create_default_wifi_sta();
    s_ap_netif = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    // Create a persistent event group so the event handler can always post connection
    // results without racing with temporary per-attempt groups.
    if (!s_wifi_event_group) {
        s_wifi_event_group = xEventGroupCreate();
    }
    ensure_state_lock();
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_AP_STAIPASSIGNED, &event_handler, NULL);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_err_t start_ret = esp_wifi_start();
    if (!wifi_mark_started(start_ret)){
        ESP_LOGW(TAG, "esp_wifi_start() during init -> %d", start_ret);
    }
}

bool wifi_connect(const char* ssid, const char* pass, int timeout_sec){
    wifi_config_t sta_cfg = {};
    strncpy((char*)sta_cfg.sta.ssid, ssid, sizeof(sta_cfg.sta.ssid));
    if (pass && pass[0] != '\0') {
        strncpy((char*)sta_cfg.sta.password, pass, sizeof(sta_cfg.sta.password));
    } else {
        memset(sta_cfg.sta.password, 0, sizeof(sta_cfg.sta.password));
    }
    sta_cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;
    sta_cfg.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;

    // Do not stop the HTTP server here — keep the web UI available while
    // attempting to connect. If we're currently running as an AP, switch
    // to APSTA mode so the AP remains active while we attempt the STA
    // connection. The caller (e.g. configure_post) will stop the AP/server
    // after a successful connection.
    if (s_ap_running) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
    } else {
        esp_wifi_set_mode(WIFI_MODE_STA);
    }
    esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);

    // Clear previous bits then connect and wait for hit or fail
    ESP_LOGI(TAG, "wifi_connect: ssid='%s' timeout=%d", ssid ? ssid : "(null)", timeout_sec);
    if (s_wifi_event_group) xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
    esp_err_t ret = esp_wifi_connect();
    ESP_LOGI(TAG, "esp_wifi_connect() -> %d", ret);
    EventBits_t bits = s_wifi_event_group ? xEventGroupWaitBits(s_wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdTRUE, pdFALSE,
                                           pdMS_TO_TICKS(timeout_sec * 1000)) : 0;
    ESP_LOGI(TAG, "wifi_connect result bits=0x%02x", bits);
    bool connected = bits & WIFI_CONNECTED_BIT;
    if (connected && wifi_scan_is_active()){
        wifi_scan_stop();
    }
    return connected;
}

void wifi_ap_start(){
    wifi_config_t ap_cfg = {};
    // Fallback to string literals if Kconfig symbols are not defined
#ifndef CONFIG_APP_WIFI_SOFTAP_SSID
#define CONFIG_APP_WIFI_SOFTAP_SSID "ESP32-HID-Setup"
#endif
#ifndef CONFIG_APP_WIFI_SOFTAP_CHANNEL
#define CONFIG_APP_WIFI_SOFTAP_CHANNEL 6
#endif
    strncpy((char*)ap_cfg.ap.ssid, CONFIG_APP_WIFI_SOFTAP_SSID, sizeof(ap_cfg.ap.ssid));
    ap_cfg.ap.ssid_len = 0;
    ap_cfg.ap.channel = CONFIG_APP_WIFI_SOFTAP_CHANNEL;
    ap_cfg.ap.max_connection = 4;

#ifndef CONFIG_APP_WIFI_SOFTAP_PASSWORD
#define CONFIG_APP_WIFI_SOFTAP_PASSWORD ""
#endif
    const char* configured_pass = CONFIG_APP_WIFI_SOFTAP_PASSWORD;
    const char* default_pass = "uhid1234";
    bool use_default_pass = false;

    ap_cfg.ap.authmode = WIFI_AUTH_WPA2_PSK;
    if (!configured_pass || configured_pass[0] == '\0') {
        ESP_LOGW(TAG, "SoftAP password not provided; using default provisioning password");
        use_default_pass = true;
    } else {
        size_t resolved_len = strnlen(configured_pass, sizeof(ap_cfg.ap.password));
        if (resolved_len < 8) {
            ESP_LOGW(TAG,
                     "SoftAP password is %u characters; WPA2 requires at least 8. Starting open AP.",
                     (unsigned)resolved_len);
            ap_cfg.ap.authmode = WIFI_AUTH_OPEN;
            memset(ap_cfg.ap.password, 0, sizeof(ap_cfg.ap.password));
        } else {
            strncpy((char*)ap_cfg.ap.password, configured_pass, sizeof(ap_cfg.ap.password));
        }
    }
    ap_cfg.ap.password[sizeof(ap_cfg.ap.password) - 1] = '\0';
    if (ap_cfg.ap.authmode == WIFI_AUTH_WPA2_PSK && ap_cfg.ap.password[0] == '\0') {
        // If the configured password was empty, ensure we still use the default.
        const char* resolved_pass = use_default_pass ? default_pass : configured_pass;
        strncpy((char*)ap_cfg.ap.password, resolved_pass ? resolved_pass : default_pass,
                sizeof(ap_cfg.ap.password));
        ap_cfg.ap.password[sizeof(ap_cfg.ap.password) - 1] = '\0';
    }
    // Ensure WiFi is stopped before changing mode to reliably start AP
    // Stop any running HTTP server first to avoid active socket operations
    extern void http_server_stop();
    http_server_stop();
    // small delay to allow httpd background workers/sockets to close
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_err_t stop_ret = esp_wifi_stop();
    if (!wifi_mark_stopped(stop_ret)){
        ESP_LOGW(TAG, "wifi_ap_start: esp_wifi_stop() -> %d", stop_ret);
    }
    // small delay after stop to let controller settle
    vTaskDelay(pdMS_TO_TICKS(200));
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);
    esp_err_t ret = esp_wifi_start();
    wifi_mark_started(ret);
    ESP_LOGI(TAG, "esp_wifi_start() for AP -> %d", ret);
}

void wifi_ap_stop(){
    // Stop HTTP server for the AP interface only if no STA connection
    // will take over. This keeps the configuration UI responsive while
    // clients migrate to the STA address.
    if (!wifi_sta_is_connected()){
        extern void http_server_stop();
        http_server_stop();
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    wifi_mode_t cur_mode = WIFI_MODE_NULL;
    esp_err_t em = esp_wifi_get_mode(&cur_mode);
    if (em != ESP_OK) {
        ESP_LOGW(TAG, "wifi_ap_stop: esp_wifi_get_mode -> %d", em);
    }
    if (cur_mode == WIFI_MODE_APSTA) {
        // switch to STA only so we keep any ongoing STA connection
        esp_err_t r = esp_wifi_set_mode(WIFI_MODE_STA);
        ESP_LOGI(TAG, "wifi_ap_stop: switched mode APSTA->STA -> %d", r);
    } else if (cur_mode == WIFI_MODE_AP) {
        // stop Wi-Fi entirely
        esp_err_t stop_ret = esp_wifi_stop();
        if (!wifi_mark_stopped(stop_ret)){
            ESP_LOGW(TAG, "wifi_ap_stop: esp_wifi_stop -> %d", stop_ret);
        }
        esp_wifi_set_mode(WIFI_MODE_NULL);
        ESP_LOGI(TAG, "wifi_ap_stop: stopped AP-only wifi");
    } else {
        ESP_LOGI(TAG, "wifi_ap_stop: no AP mode active (cur_mode=%d)", cur_mode);
    }
}

bool wifi_is_ap(){ return s_ap_running; }

std::vector<scan_result_t> wifi_scan_safe(){
    return wifi_scan();
}

std::vector<scan_result_t> wifi_scan(){
    std::vector<scan_result_t> out;
    wifi_scan_config_t sc = {};
    // Track original state so we can restore when done.
    wifi_mode_t prev_mode = WIFI_MODE_NULL;
    esp_wifi_get_mode(&prev_mode);
    bool prev_started = s_wifi_started;

    wifi_mode_t desired_mode = prev_mode;
    if (s_ap_running) {
        desired_mode = WIFI_MODE_APSTA;
    } else if (prev_mode == WIFI_MODE_NULL) {
        desired_mode = WIFI_MODE_STA;
    } else if (prev_mode == WIFI_MODE_APSTA || prev_mode == WIFI_MODE_STA) {
        desired_mode = prev_mode;
    } else {
        desired_mode = WIFI_MODE_STA;
    }

    bool changed_mode = false;
    if (desired_mode != prev_mode) {
        esp_err_t mr = esp_wifi_set_mode(desired_mode);
        if (mr != ESP_OK) {
            ESP_LOGW(TAG, "wifi_scan: esp_wifi_set_mode(%d) -> %d", desired_mode, mr);
        } else {
            changed_mode = true;
        }
    }

    bool started_for_scan = false;
    bool started_now = prev_started;
    if (!started_now) {
        esp_err_t sr = esp_wifi_start();
        bool started_ok = wifi_mark_started(sr);
        if (!started_ok) {
            ESP_LOGW(TAG, "wifi_scan: esp_wifi_start() -> %d", sr);
        } else {
            started_for_scan = (sr == ESP_OK) && !prev_started;
            started_now = true;
        }
    }

    esp_err_t r = ESP_ERR_WIFI_STATE;
    int64_t scan_start = 0;
    if (started_now) {
        scan_start = esp_timer_get_time();
        r = esp_wifi_scan_start(&sc, true);
    }
    if (r == ESP_OK) {
        // measure scan time for diagnostics
        uint16_t n = 0;
        esp_wifi_scan_get_ap_num(&n);
        std::vector<wifi_ap_record_t> recs(n);
        esp_wifi_scan_get_ap_records(&n, recs.data());
        int64_t scan_end = esp_timer_get_time();
        ESP_LOGI(TAG, "wifi_scan: found %d APs, scan_time_ms=%d", n, (int)((scan_end - scan_start) / 1000));
        out.reserve(n);
        for (uint16_t i=0;i<n;i++){
            scan_result_t rrec;
            rrec.ssid = (const char*)recs[i].ssid;
            rrec.rssi = recs[i].rssi;
            out.push_back(rrec);
        }
    } else {
        ESP_LOGW(TAG, "wifi_scan: esp_wifi_scan_start -> %d", r);
    }
    // restore previous mode/start state if we changed it
    if (changed_mode && prev_mode != WIFI_MODE_NULL) {
        esp_err_t mr = esp_wifi_set_mode(prev_mode);
        if (mr != ESP_OK) {
            ESP_LOGW(TAG, "wifi_scan: esp_wifi_set_mode(restore=%d) -> %d", prev_mode, mr);
        } else {
            if (prev_started && !s_wifi_started) {
                esp_err_t sr = esp_wifi_start();
                if (!wifi_mark_started(sr)) {
                    ESP_LOGW(TAG, "wifi_scan: esp_wifi_start (restore) -> %d", sr);
                }
            }
        }
    }
    if (started_for_scan) {
        esp_err_t sr = esp_wifi_stop();
        if (!wifi_mark_stopped(sr)) {
            ESP_LOGW(TAG, "wifi_scan: esp_wifi_stop (restore) -> %d", sr);
        }
        esp_wifi_set_mode(WIFI_MODE_NULL);
    }
    return out;
}

static void wifi_scan_task(void *pv){
    while (s_scan_active){
        auto scan = wifi_scan();
        if (!s_scan_lock) s_scan_lock = xSemaphoreCreateMutex();
        if (s_scan_lock){
            xSemaphoreTake(s_scan_lock, portMAX_DELAY);
            s_last_scan = scan;
            xSemaphoreGive(s_scan_lock);
        }
        // scan interval when active
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
    s_scan_task = NULL;
    vTaskDelete(NULL);
}

void wifi_scan_start(){
    if (s_scan_active) return;
    s_scan_active = true;
    if (!s_scan_lock) s_scan_lock = xSemaphoreCreateMutex();
    xTaskCreate(wifi_scan_task, "wifi_scan", 4096, NULL, 5, &s_scan_task);
}

void wifi_scan_stop(){
    s_scan_active = false;
    // task will self-delete; clear cached results
    if (s_scan_lock){
        xSemaphoreTake(s_scan_lock, portMAX_DELAY);
        s_last_scan.clear();
        xSemaphoreGive(s_scan_lock);
    }
}

bool wifi_scan_is_active(){ return s_scan_active; }

std::vector<scan_result_t> wifi_get_last_scan(){
    std::vector<scan_result_t> out;
    if (s_scan_lock){
        xSemaphoreTake(s_scan_lock, portMAX_DELAY);
        out = s_last_scan;
        xSemaphoreGive(s_scan_lock);
    }
    return out;
}

std::string wifi_get_sta_ip(){
    ensure_state_lock();
    if (s_state_lock){
        xSemaphoreTake(s_state_lock, portMAX_DELAY);
        if (!s_last_sta_ip.empty()){
            std::string cached = s_last_sta_ip;
            xSemaphoreGive(s_state_lock);
            return cached;
        }
        xSemaphoreGive(s_state_lock);
    }
    if (!s_sta_netif) return std::string();
    esp_netif_ip_info_t info;
    if (esp_netif_get_ip_info(s_sta_netif, &info) != ESP_OK) return std::string();
    char buf[32];
    esp_ip4addr_ntoa(&info.ip, buf, sizeof(buf));
    std::string out(buf);
    if (s_state_lock){
        xSemaphoreTake(s_state_lock, portMAX_DELAY);
        s_last_sta_ip = out;
        xSemaphoreGive(s_state_lock);
    }
    return out;
}

std::string wifi_get_ap_ip(){
    if (!s_ap_netif) return std::string();
    esp_netif_ip_info_t info;
    if (esp_netif_get_ip_info(s_ap_netif, &info) != ESP_OK) return std::string();
    char buf[32];
    esp_ip4addr_ntoa(&info.ip, buf, sizeof(buf));
    return std::string(buf);
}

std::string wifi_get_connected_ssid(){
    wifi_ap_record_t rec;
    if (esp_wifi_sta_get_ap_info(&rec) == ESP_OK){
        return std::string((const char*)rec.ssid);
    }
    return std::string();
}

bool wifi_try_sta_then_ap(const char* ssid_opt, const char* pass_opt, int timeout_sec){
    bool ok = false;
    if (ssid_opt && *ssid_opt){
        ok = wifi_connect(ssid_opt, pass_opt ? pass_opt : "", timeout_sec);
    } else {
        // Try auto-connect with stored creds (if any)
        // Ensure previous connection bits are cleared, then start and wait
        ESP_LOGI(TAG, "auto-connect: starting STA auto-connect (timeout=%d)", timeout_sec);
        if (s_wifi_event_group) xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_err_t start_ret = esp_wifi_start();
    if (!wifi_mark_started(start_ret)) {
        ESP_LOGW(TAG, "auto-connect: esp_wifi_start -> %d", start_ret);
    }
    esp_wifi_connect();
        EventBits_t bits = s_wifi_event_group ? xEventGroupWaitBits(s_wifi_event_group,
                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                           pdTRUE, pdFALSE,
                           pdMS_TO_TICKS(timeout_sec * 1000)) : 0;
        ESP_LOGI(TAG, "auto-connect result bits=0x%02x", bits);
        ok = bits & WIFI_CONNECTED_BIT;
    }
    if (!ok){
        ESP_LOGI(TAG, "STA failed or timed out, starting AP fallback");
        wifi_ap_start();
    }
    if (ok && wifi_scan_is_active()){
        wifi_scan_stop();
    }
    return ok;
}

std::vector<ap_client_info_t> wifi_get_ap_clients(int* total_count_out){
    wifi_sta_list_t sta_list = {};
    esp_err_t ret = esp_wifi_ap_get_sta_list(&sta_list);
    if (total_count_out){
        *total_count_out = (ret == ESP_OK) ? sta_list.num : 0;
    }
    std::vector<ap_client_info_t> out;
    if (ret != ESP_OK || sta_list.num <= 0){
        return out;
    }
    out.reserve(sta_list.num);
    ensure_state_lock();
    if (s_state_lock){
        xSemaphoreTake(s_state_lock, portMAX_DELAY);
    }
    for (int i = 0; i < sta_list.num; ++i){
        ap_client_info_t info{};
        std::copy(sta_list.sta[i].mac, sta_list.sta[i].mac + 6, info.mac.begin());
        info.rssi = sta_list.sta[i].rssi;
        info.has_ip = false;
        info.ip = 0;
        if (s_state_lock){
            auto it = s_ap_client_state.find(mac_to_key(sta_list.sta[i].mac));
            if (it != s_ap_client_state.end()){
                info.has_ip = it->second.has_ip;
                info.ip = it->second.ip;
            }
        }
        out.push_back(info);
    }
    if (s_state_lock){
        xSemaphoreGive(s_state_lock);
    }
    return out;
}

bool wifi_sta_is_connected(){
    ensure_state_lock();
    if (!s_state_lock){
        return false;
    }
    xSemaphoreTake(s_state_lock, portMAX_DELAY);
    bool connected = s_sta_connected;
    xSemaphoreGive(s_state_lock);
    return connected;
}

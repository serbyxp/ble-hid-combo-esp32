#pragma once
#include "esp_err.h"
#include <vector>
#include <string>
#include <array>

typedef struct {
    std::string ssid;
    int rssi;
} scan_result_t;

struct ap_client_info_t {
    std::array<uint8_t, 6> mac;
    int rssi;
    bool has_ip;
    uint32_t ip; // IPv4, network byte order (same as esp_ip4_addr_t::addr)
};

void wifi_mgr_init();
bool wifi_try_sta_then_ap(const char* ssid_opt, const char* pass_opt, int timeout_sec);
std::vector<scan_result_t> wifi_scan();
// NOTE: wifi_scan() will attempt to perform a scan; the implementation
// should ensure it does not destroy the AP when scanning (e.g. use APSTA).
bool wifi_connect(const char* ssid, const char* pass, int timeout_sec);
void wifi_ap_start();
void wifi_ap_stop();
bool wifi_is_ap();

// Scan control: start/stop background scanning (returns immediately)
void wifi_scan_start();
void wifi_scan_stop();
bool wifi_scan_is_active();

// Get last scan results (thread-safe snapshot)
std::vector<scan_result_t> wifi_get_last_scan();

// Status helpers
std::string wifi_get_sta_ip();
std::string wifi_get_ap_ip();
std::string wifi_get_connected_ssid();
std::vector<ap_client_info_t> wifi_get_ap_clients(int* total_count_out = nullptr);
bool wifi_sta_is_connected();

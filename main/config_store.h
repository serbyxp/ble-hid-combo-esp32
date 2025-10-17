#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool enable_wifi;
    bool enable_web;
    bool enable_uart;
} bridge_toggles_t;

void cfg_init(void);
void cfg_save_toggles(const bridge_toggles_t* t);
bridge_toggles_t cfg_load_toggles(void);

// Optional: store last known SSID for UX (ESP-IDF stores actual creds)
void cfg_set_last_ssid(const char* ssid);
void cfg_get_last_ssid(char* out, size_t len);

#ifdef __cplusplus
}
#endif

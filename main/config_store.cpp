#include "config_store.h"
#include "nvs_flash.h"
#include "nvs.h"
#include <string.h>

#define NS "cfg"

void cfg_init(void){
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
}

void cfg_save_toggles(const bridge_toggles_t* t){
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) == ESP_OK){
        nvs_set_u8(h, "wifi", t->enable_wifi);
        nvs_set_u8(h, "web",  t->enable_web);
        nvs_set_u8(h, "uart", t->enable_uart);
        nvs_commit(h);
        nvs_close(h);
    }
}

bridge_toggles_t cfg_load_toggles(void){
    bridge_toggles_t t{true, true, true};
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) == ESP_OK){
        uint8_t v;
        if (nvs_get_u8(h, "wifi", &v) == ESP_OK) t.enable_wifi = v;
        if (nvs_get_u8(h, "web",  &v) == ESP_OK) t.enable_web  = v;
        if (nvs_get_u8(h, "uart", &v) == ESP_OK) t.enable_uart = v;
        nvs_close(h);
    }
    return t;
}

void cfg_set_last_ssid(const char* ssid){
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) == ESP_OK){
        nvs_set_str(h, "ssid", ssid ? ssid : "");
        nvs_commit(h);
        nvs_close(h);
    }
}

void cfg_get_last_ssid(char* out, size_t len){
    if (!out || len == 0) return;
    out[0] = 0;
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) == ESP_OK){
        size_t n = len;
        if (nvs_get_str(h, "ssid", out, &n) != ESP_OK) out[0] = 0;
        nvs_close(h);
    }
}

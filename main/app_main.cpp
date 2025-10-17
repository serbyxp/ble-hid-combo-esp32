#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "wifi_mgr.h"
#include "http_server.h"
#include "ble_hid.h"
#include "uart_bridge.h"
#include "config_store.h"

static const char* TAG = "app_main";
// silence unused variable warning in some build configs
static void __unused_app_main_tag(void){ (void)TAG; }

extern "C" void app_main(void){
    cfg_init();
    bridge_toggles_t t = cfg_load_toggles();

    if (t.enable_wifi) {
        // Wi-Fi init + attempt STA then AP fallback
        wifi_mgr_init();
        wifi_try_sta_then_ap(nullptr, nullptr, 6);

        if (t.enable_web) {
            http_server_start();
        }
    } else {
        ESP_LOGI(TAG, "Wi-Fi disabled via configuration; skipping Wi-Fi setup");
        if (t.enable_web) {
            ESP_LOGW(TAG, "Web UI requested but Wi-Fi is disabled; HTTP server not started");
        }
    }

    // BLE HID device
    ble_hid_start("uHID");

    // UART bridge default ON
    if (t.enable_uart) {
        uart_bridge_start();
    }

    // Example: periodic demo (optional)
    while (true){
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

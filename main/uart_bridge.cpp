#include "uart_bridge.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "ble_hid.h"
#include "cJSON.h"
#include "config_store.h"
#include <atomic>
#include <cstring>

static const char *TAG = "uart_bridge";

// forward declaration for the task function used below
static void uart_bridge_task(void *);
static std::atomic<bool> s_uart_rx_seen{false};
static const char READY_MSG[] = "{\"type\":\"status\",\"event\":\"ready\"}\n";

static void handle_json(const char *s)
{
    cJSON *root = cJSON_Parse(s);
    if (!root)
        return;
    const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(root, "type"));
    if (type && strcmp(type, "mouse") == 0)
    {
        int dx = cJSON_GetNumberValue(cJSON_GetObjectItem(root, "dx"));
        int dy = cJSON_GetNumberValue(cJSON_GetObjectItem(root, "dy"));
        int wh = cJSON_GetNumberValue(cJSON_GetObjectItem(root, "wheel"));
        int b1 = cJSON_GetNumberValue(cJSON_GetObjectItem(root, "b1"));
        int b2 = cJSON_GetNumberValue(cJSON_GetObjectItem(root, "b2"));
        int b3 = cJSON_GetNumberValue(cJSON_GetObjectItem(root, "b3"));
        uint8_t buttons = (b1 ? 1 : 0) | (b2 ? 2 : 0) | (b3 ? 4 : 0);
        ble_hid_notify_mouse((int8_t)dx, (int8_t)dy, (int8_t)wh, buttons);
    }
    else if (type && strcmp(type, "key") == 0)
    {
        uint8_t mods = (uint8_t)cJSON_GetNumberValue(cJSON_GetObjectItem(root, "mods"));
        uint8_t keys[6] = {0};
        cJSON *arr = cJSON_GetObjectItem(root, "keys");
        int i = 0;
        if (cJSON_IsArray(arr))
        {
            cJSON *it = nullptr;
            cJSON_ArrayForEach(it, arr)
            {
                if (i < 6)
                    keys[i++] = (uint8_t)cJSON_GetNumberValue(it);
            }
        }
        ble_hid_kbd_set(mods, keys);
        ble_hid_notify_kbd();
    }
    else if (type && strcmp(type, "battery") == 0)
    {
        int pct = cJSON_GetNumberValue(cJSON_GetObjectItem(root, "pct"));
        if (pct < 0)
            pct = 0;
        if (pct > 100)
            pct = 100;
        ble_hid_set_battery((uint8_t)pct);
    }
    else if (type && strcmp(type, "config") == 0)
    {
        bridge_toggles_t t = cfg_load_toggles();
        cJSON *v;
        if ((v = cJSON_GetObjectItem(root, "wifi")))
            t.enable_wifi = cJSON_IsTrue(v);
        if ((v = cJSON_GetObjectItem(root, "web")))
            t.enable_web = cJSON_IsTrue(v);
        if ((v = cJSON_GetObjectItem(root, "uart")))
            t.enable_uart = cJSON_IsTrue(v);
        cfg_save_toggles(&t);
    }
    cJSON_Delete(root);
}

void uart_bridge_start()
{
    const uart_port_t uart = UART_NUM_0;
    uart_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.baud_rate = 115200;
    cfg.data_bits = UART_DATA_8_BITS;
    cfg.parity = UART_PARITY_DISABLE;
    cfg.stop_bits = UART_STOP_BITS_1;
    cfg.flow_ctrl = UART_HW_FLOWCTRL_DISABLE;
    cfg.rx_flow_ctrl_thresh = 0;
    cfg.source_clk = UART_SCLK_DEFAULT;
    uart_param_config(uart, &cfg);
    uart_driver_install(uart, 4096, 0, 0, NULL, 0);
    ESP_LOGI(TAG, "starting uart bridge");
    xTaskCreate(uart_bridge_task, "uart_bridge", 4096, NULL, 5, NULL);
}

static void uart_bridge_task(void *)
{
    char line[512];
    int pos = 0;
    uart_write_bytes(UART_NUM_0, READY_MSG, strlen(READY_MSG));
    while (1)
    {
        uint8_t b;
        int n = uart_read_bytes(UART_NUM_0, &b, 1, portMAX_DELAY);
        if (n == 1)
        {
            s_uart_rx_seen.store(true, std::memory_order_relaxed);
            if (b == '\n' || b == '\r')
            {
                line[pos] = 0;
                if (pos > 0)
                    handle_json(line);
                pos = 0;
            }
            else if (pos < (int)sizeof(line) - 1)
            {
                line[pos++] = (char)b;
            }
            else
            {
                pos = 0;
            }
        }
    }
}

bool uart_bridge_has_seen_data()
{
    return s_uart_rx_seen.load(std::memory_order_relaxed);
}

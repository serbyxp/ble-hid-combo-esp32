#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    void ble_hid_start(const char *name);
    void ble_hid_notify_mouse(int8_t dx, int8_t dy, int8_t wheel, uint8_t buttons);
    void ble_hid_kbd_set(uint8_t modifiers, const uint8_t keys[6]);
    void ble_hid_notify_kbd(void);
    void ble_hid_set_battery(uint8_t pct);

    typedef void (*kbd_out_cb_t)(const uint8_t report[8]);
    void ble_hid_set_kbd_out_callback(kbd_out_cb_t cb);
    void ble_hid_restart_advertising(void);
    bool ble_hid_is_connected(void);

#define BLE_HID_MAX_PEER_NAME 32

    typedef struct
    {
        uint8_t addr_type;
        uint8_t addr[6];
        char name[BLE_HID_MAX_PEER_NAME];
        bool connected;
    } ble_hid_peer_info_t;

    size_t ble_hid_get_bonded_peers(ble_hid_peer_info_t *peers, size_t max_peers);
    bool ble_hid_forget_peer(uint8_t addr_type, const uint8_t addr[6]);
    int ble_hid_get_bonded_count(void);
    int ble_hid_clear_bonded_peers(void);

#ifdef __cplusplus
}
#endif

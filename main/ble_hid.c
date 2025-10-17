#include "ble_hid.h"
#include <stdbool.h>
#include "esp_log.h"
#include "esp_bt.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_hs_id.h"
#include "host/ble_hs_mbuf.h"
#include "host/ble_sm.h"
#include "os/os_mbuf.h"
#include "store/config/ble_store_config.h"
#include "host/ble_store.h"
#include "host/ble_gap.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h>

#include "nimble/hci_common.h"

extern void ble_store_config_init(void);
extern int ble_store_util_delete_peer(const ble_addr_t *peer_addr);

static const char *TAG = "ble_hid";
// Store device name for host task (avoid nested functions / trampolines)
static const char *s_device_name = NULL;
static uint8_t s_own_addr_type;
static bool s_ble_connected = false;
static uint16_t s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static bool s_nimble_ready = false;
static bool s_connected_peer_valid = false;
static ble_addr_t s_connected_peer = {0};

// UUIDs
#define UUID16_HID_SERVICE 0x1812
#define UUID16_BAS_SERVICE 0x180F
#define UUID16_HID_INFO 0x2A4A
#define UUID16_REPORT_MAP 0x2A4B
#define UUID16_HID_CTRL 0x2A4C
#define UUID16_HID_REPORT 0x2A4D
#define UUID16_PROTO_MODE 0x2A4E
#define UUID16_BATT_LEVEL 0x2A19
#define UUID16_REPORT_REF 0x2908

// Report types
#define REPORT_TYPE_INPUT 0x01
#define REPORT_TYPE_OUTPUT 0x02

// Appearance Mouse
#define APPEARANCE_MOUSE 962

// Report IDs
#define REPORT_ID_MOUSE 1
#define REPORT_ID_KEYBOARD 2
#define REPORT_ID_CONSUMER 3

// Report state
static uint8_t s_mouse_state[4] = {0};
static uint8_t s_kbd_in[8] = {0};
static uint8_t s_kbd_out[8] = {0};
static uint8_t s_consumer_state[2] = {0};
static uint8_t s_batt = 100;
static kbd_out_cb_t s_kbd_cb = NULL;

static uint16_t h_mouse_rep = 0;
static uint16_t h_mouse_ctrl = 0;
static uint16_t h_mouse_proto = 0;
static uint16_t h_kbd_in = 0;
static uint16_t h_kbd_out = 0;
static uint16_t h_kbd_ctrl = 0;
static uint16_t h_kbd_proto = 0;
static uint16_t h_consumer_in = 0;
static uint16_t h_consumer_ctrl = 0;
static uint16_t h_consumer_proto = 0;
static uint16_t h_batt = 0;

static uint8_t s_mouse_ctrl_point = 0;
static uint8_t s_mouse_proto_mode = 1;
static uint8_t s_kbd_ctrl_point = 0;
static uint8_t s_kbd_proto_mode = 1;
static uint8_t s_consumer_ctrl_point = 0;
static uint8_t s_consumer_proto_mode = 1;

static int gap_event(struct ble_gap_event *event, void *arg);
static void ensure_security(uint16_t conn_handle);
static void log_conn_security(uint16_t conn_handle, const char *context);

static uint8_t *ctrl_point_for_handle(uint16_t handle)
{
    if (handle == h_mouse_ctrl)
    {
        return &s_mouse_ctrl_point;
    }
    if (handle == h_kbd_ctrl)
    {
        return &s_kbd_ctrl_point;
    }
    if (handle == h_consumer_ctrl)
    {
        return &s_consumer_ctrl_point;
    }
    return NULL;
}

static uint8_t *proto_mode_for_handle(uint16_t handle)
{
    if (handle == h_mouse_proto)
    {
        return &s_mouse_proto_mode;
    }
    if (handle == h_kbd_proto)
    {
        return &s_kbd_proto_mode;
    }
    if (handle == h_consumer_proto)
    {
        return &s_consumer_proto_mode;
    }
    return NULL;
}

static int chr_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                         struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    uint16_t uuid = ble_uuid_u16(ctxt->chr->uuid);
    if (uuid == UUID16_HID_REPORT)
    {
        if (attr_handle == h_mouse_rep)
        {
            if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR)
            {
                return os_mbuf_append(ctxt->om, s_mouse_state, sizeof(s_mouse_state)) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
            }
        }
        else if (attr_handle == h_kbd_in)
        {
            if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR)
            {
                return os_mbuf_append(ctxt->om, s_kbd_in, sizeof(s_kbd_in)) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
            }
        }
        else if (attr_handle == h_kbd_out)
        {
            if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR)
            {
                return os_mbuf_append(ctxt->om, s_kbd_out, sizeof(s_kbd_out)) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
            }
            else if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR)
            {
                int len = OS_MBUF_PKTLEN(ctxt->om);
                if (len > 8)
                    len = 8;
                os_mbuf_copydata(ctxt->om, 0, len, s_kbd_out);
                if (s_kbd_cb)
                    s_kbd_cb(s_kbd_out);
                return 0;
            }
        }
        else if (attr_handle == h_consumer_in)
        {
            if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR)
            {
                return os_mbuf_append(ctxt->om, s_consumer_state, sizeof(s_consumer_state)) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
            }
        }
    }
    else if (uuid == UUID16_HID_CTRL)
    {
        uint8_t *ctrl = ctrl_point_for_handle(attr_handle);
        if (!ctrl)
        {
            return BLE_ATT_ERR_UNLIKELY;
        }
        if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR)
        {
            return os_mbuf_append(ctxt->om, ctrl, 1) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR)
        {
            uint8_t val = 0;
            if (OS_MBUF_PKTLEN(ctxt->om) > 0)
            {
                os_mbuf_copydata(ctxt->om, 0, 1, &val);
            }
            *ctrl = val;
        }
    }
    else if (uuid == UUID16_PROTO_MODE)
    {
        uint8_t *mode = proto_mode_for_handle(attr_handle);
        if (!mode)
        {
            return BLE_ATT_ERR_UNLIKELY;
        }
        if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR)
        {
            return os_mbuf_append(ctxt->om, mode, 1) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR)
        {
            uint8_t val = 0;
            if (OS_MBUF_PKTLEN(ctxt->om) > 0)
            {
                os_mbuf_copydata(ctxt->om, 0, 1, &val);
                val = (val != 0);
            }
            *mode = val;
        }
    }
    else if (uuid == UUID16_BATT_LEVEL)
    {
        if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR)
        {
            return os_mbuf_append(ctxt->om, &s_batt, 1) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
    }
    else if (uuid == UUID16_HID_INFO)
    {
        static const uint8_t hid_info[4] = {0x01, 0x01, 0x00, 0x00};
        return os_mbuf_append(ctxt->om, hid_info, sizeof(hid_info)) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    else if (uuid == UUID16_REPORT_MAP)
    {
        // Not used here: repmap handlers provide content
    }
    return 0;
}

static int dsc_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                         struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    uint16_t uuid = ble_uuid_u16(ctxt->dsc->uuid);
    if (uuid == UUID16_REPORT_REF)
    {
        uint8_t ref[2];
        ref[0] = ((uintptr_t)arg) & 0xFF;        // report ID
        ref[1] = (((uintptr_t)arg) >> 8) & 0xFF; // type
        return os_mbuf_append(ctxt->om, ref, 2) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    return 0;
}

// Predefined Report Maps (verbatim)
static const uint8_t MOUSE_REPORT[] = {
    0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x85, REPORT_ID_MOUSE, 0x09, 0x01, 0xA1, 0x00,
    0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, 0x95, 0x03,
    0x75, 0x01, 0x81, 0x02, 0x95, 0x01, 0x75, 0x05, 0x81, 0x03, 0x05, 0x01,
    0x09, 0x30, 0x09, 0x31, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08,
    0x95, 0x03, 0x81, 0x06, 0xC0, 0xC0};
static const uint8_t KEYBOARD_REPORT[] = {
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, REPORT_ID_KEYBOARD, 0x75, 0x01, 0x95, 0x08,
    0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x81, 0x02,
    0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05, 0x75, 0x01, 0x05, 0x08,
    0x19, 0x01, 0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01,
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00,
    0x29, 0x65, 0x81, 0x00, 0xC0};
static const uint8_t CONSUMER_REPORT[] = {
    0x05, 0x0C, 0x09, 0x01, 0xA1, 0x01, 0x85, REPORT_ID_CONSUMER, 0x15, 0x00,
    0x26, 0x9C, 0x02, 0x19, 0x00, 0x2A, 0x9C, 0x02, 0x95, 0x01, 0x75, 0x10,
    0x81, 0x00, 0xC0};

static int start_advertising(const char *name);

// Characteristic value providers for the fixed reports
static int repmap_mouse_cb(uint16_t conn_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    return os_mbuf_append(ctxt->om, MOUSE_REPORT, sizeof(MOUSE_REPORT)) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}
static int repmap_kbd_cb(uint16_t conn_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    return os_mbuf_append(ctxt->om, KEYBOARD_REPORT, sizeof(KEYBOARD_REPORT)) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}
static int repmap_consumer_cb(uint16_t conn_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    return os_mbuf_append(ctxt->om, CONSUMER_REPORT, sizeof(CONSUMER_REPORT)) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static const struct ble_gatt_svc_def gatt_svcs[] = {
    // Mouse HID service (RID=1)
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(UUID16_HID_SERVICE),
        .characteristics = (struct ble_gatt_chr_def[]){
            {.uuid = BLE_UUID16_DECLARE(UUID16_HID_INFO), .access_cb = chr_access_cb, .flags = BLE_GATT_CHR_F_READ},
            {.uuid = BLE_UUID16_DECLARE(UUID16_REPORT_MAP), .access_cb = repmap_mouse_cb, .flags = BLE_GATT_CHR_F_READ},
            {.uuid = BLE_UUID16_DECLARE(UUID16_HID_CTRL), .access_cb = chr_access_cb, .val_handle = &h_mouse_ctrl, .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP},
            {.uuid = BLE_UUID16_DECLARE(UUID16_HID_REPORT), .access_cb = chr_access_cb, .val_handle = &h_mouse_rep, .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY, .descriptors = (struct ble_gatt_dsc_def[]){{.uuid = BLE_UUID16_DECLARE(UUID16_REPORT_REF), .att_flags = BLE_ATT_F_READ, .access_cb = dsc_access_cb, .arg = (void *)(uintptr_t)((REPORT_ID_MOUSE) | (REPORT_TYPE_INPUT << 8))}, {0}}},
            {.uuid = BLE_UUID16_DECLARE(UUID16_PROTO_MODE), .access_cb = chr_access_cb, .val_handle = &h_mouse_proto, .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP},
            {0}}},
    // Keyboard HID service (RID=2)
    {.type = BLE_GATT_SVC_TYPE_PRIMARY, .uuid = BLE_UUID16_DECLARE(UUID16_HID_SERVICE), .characteristics = (struct ble_gatt_chr_def[]){{.uuid = BLE_UUID16_DECLARE(UUID16_HID_INFO), .access_cb = chr_access_cb, .flags = BLE_GATT_CHR_F_READ}, {.uuid = BLE_UUID16_DECLARE(UUID16_REPORT_MAP), .access_cb = repmap_kbd_cb, .flags = BLE_GATT_CHR_F_READ}, {.uuid = BLE_UUID16_DECLARE(UUID16_HID_CTRL), .access_cb = chr_access_cb, .val_handle = &h_kbd_ctrl, .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP}, {.uuid = BLE_UUID16_DECLARE(UUID16_HID_REPORT), .access_cb = chr_access_cb, .val_handle = &h_kbd_in, .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY, .descriptors = (struct ble_gatt_dsc_def[]){{.uuid = BLE_UUID16_DECLARE(UUID16_REPORT_REF), .att_flags = BLE_ATT_F_READ, .access_cb = dsc_access_cb, .arg = (void *)(uintptr_t)((REPORT_ID_KEYBOARD) | (REPORT_TYPE_INPUT << 8))}, {0}}}, {.uuid = BLE_UUID16_DECLARE(UUID16_HID_REPORT), .access_cb = chr_access_cb, .val_handle = &h_kbd_out, .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_NOTIFY, .descriptors = (struct ble_gatt_dsc_def[]){{.uuid = BLE_UUID16_DECLARE(UUID16_REPORT_REF), .att_flags = BLE_ATT_F_READ, .access_cb = dsc_access_cb, .arg = (void *)(uintptr_t)((REPORT_ID_KEYBOARD) | (REPORT_TYPE_OUTPUT << 8))}, {0}}}, {.uuid = BLE_UUID16_DECLARE(UUID16_PROTO_MODE), .access_cb = chr_access_cb, .val_handle = &h_kbd_proto, .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP}, {0}}},
    // Consumer control HID service (RID=3)
    {.type = BLE_GATT_SVC_TYPE_PRIMARY,
     .uuid = BLE_UUID16_DECLARE(UUID16_HID_SERVICE),
     .characteristics = (struct ble_gatt_chr_def[]){
         {.uuid = BLE_UUID16_DECLARE(UUID16_HID_INFO), .access_cb = chr_access_cb, .flags = BLE_GATT_CHR_F_READ},
         {.uuid = BLE_UUID16_DECLARE(UUID16_REPORT_MAP), .access_cb = repmap_consumer_cb, .flags = BLE_GATT_CHR_F_READ},
         {.uuid = BLE_UUID16_DECLARE(UUID16_HID_CTRL), .access_cb = chr_access_cb, .val_handle = &h_consumer_ctrl, .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP},
         {.uuid = BLE_UUID16_DECLARE(UUID16_HID_REPORT),
          .access_cb = chr_access_cb,
          .val_handle = &h_consumer_in,
          .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
          .descriptors = (struct ble_gatt_dsc_def[]){
              {.uuid = BLE_UUID16_DECLARE(UUID16_REPORT_REF),
               .att_flags = BLE_ATT_F_READ,
               .access_cb = dsc_access_cb,
               .arg = (void *)(uintptr_t)((REPORT_ID_CONSUMER) | (REPORT_TYPE_INPUT << 8))},
              {0}}},
         {.uuid = BLE_UUID16_DECLARE(UUID16_PROTO_MODE), .access_cb = chr_access_cb, .val_handle = &h_consumer_proto, .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP},
         {0}}},
    // Battery Service
    {.type = BLE_GATT_SVC_TYPE_PRIMARY, .uuid = BLE_UUID16_DECLARE(UUID16_BAS_SERVICE), .characteristics = (struct ble_gatt_chr_def[]){{.uuid = BLE_UUID16_DECLARE(UUID16_BATT_LEVEL), .access_cb = chr_access_cb, .val_handle = &h_batt, .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY}, {0}}},
    {0}};

static int gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    switch (event->type)
    {
    case BLE_GAP_EVENT_CONNECT:
        ESP_LOGI(TAG, "GAP connect status=%d", event->connect.status);
        s_ble_connected = (event->connect.status == 0);
        if (event->connect.status == 0)
        {
            s_conn_handle = event->connect.conn_handle;
            struct ble_gap_conn_desc desc;
            if (ble_gap_conn_find(event->connect.conn_handle, &desc) == 0)
            {
                s_connected_peer = desc.peer_id_addr;
                s_connected_peer_valid = true;
                if (!desc.sec_state.encrypted || !desc.sec_state.bonded)
                {
                    ensure_security(event->connect.conn_handle);
                }
                else
                {
                    log_conn_security(event->connect.conn_handle, "connect");
                }
            }
            else
            {
                s_connected_peer_valid = false;
            }

        }
        else
        {
            s_connected_peer_valid = false;
            s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
            ble_hid_restart_advertising();
        }
        break;
    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "GAP disconnect");
        s_ble_connected = false;
        s_connected_peer_valid = false;
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        // restart advertising with persisted identity information
        ble_hid_restart_advertising();
        break;
    case BLE_GAP_EVENT_ENC_CHANGE:
        ESP_LOGI(TAG, "Encryption change status=%d", event->enc_change.status);
        if (event->enc_change.status == 0)
        {
            log_conn_security(event->enc_change.conn_handle, "enc_change");
        }
        else
        {
            ESP_LOGW(TAG, "Encryption failed: %d", event->enc_change.status);
            ensure_security(event->enc_change.conn_handle);
        }
        break;
    case BLE_GAP_EVENT_PASSKEY_ACTION:
    {
        const struct ble_gap_passkey_params *params = &event->passkey.params;
        ESP_LOGI(TAG, "Passkey action=%u", params->action);
        bool inject = false;
        struct ble_sm_io pkey;
        memset(&pkey, 0, sizeof(pkey));

        switch (params->action)
        {
        case BLE_SM_IOACT_NONE:
            ESP_LOGI(TAG, "Using Just Works pairing");
            break;
        case BLE_SM_IOACT_NUMCMP:
            ESP_LOGI(TAG, "Numeric comparison value=%06" PRIu32, params->numcmp);
            pkey.action = BLE_SM_IOACT_NUMCMP;
            pkey.numcmp_accept = 1;
            inject = true;
            break;
        default:
            ESP_LOGW(TAG, "Unsupported passkey action=%u", params->action);
            ble_gap_terminate(event->passkey.conn_handle, BLE_ERR_AUTH_FAIL);
            break;
        }

        if (inject)
        {
            int rc = ble_sm_inject_io(event->passkey.conn_handle, &pkey);
            if (rc != 0 && rc != BLE_HS_EALREADY)
            {
                ESP_LOGW(TAG, "ble_sm_inject_io failed: %d", rc);
            }
        }
        break;
    }
    case BLE_GAP_EVENT_REPEAT_PAIRING:
    {
        ESP_LOGW(TAG, "Repeat pairing - deleting old bond");
        ble_addr_t peer_addr = {0};
        bool have_peer = false;

        struct ble_gap_conn_desc desc;
        if (ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc) == 0)
        {
            peer_addr = desc.peer_id_addr;
            have_peer = true;
        }

        if (have_peer)
        {
            ble_store_util_delete_peer(&peer_addr);
        }
        else
        {
            ble_store_util_delete_oldest_peer();
        }
        return BLE_GAP_REPEAT_PAIRING_RETRY;
    }
    case BLE_GAP_EVENT_MTU:
        ESP_LOGI(TAG, "MTU updated: %d", event->mtu.value);
        break;
    case BLE_GAP_EVENT_PARING_COMPLETE:
        ESP_LOGI(TAG, "Pairing complete status=%d", event->pairing_complete.status);
        if (event->pairing_complete.status == 0)
        {
            log_conn_security(event->pairing_complete.conn_handle, "pairing_complete");
        }
        else
        {
            ESP_LOGW(TAG, "Pairing failed, terminating connection");
            ble_gap_terminate(event->pairing_complete.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        }
        break;
    default:
        break;
    }
    return 0;
}

bool ble_hid_is_connected(void)
{
    return s_ble_connected;
}

static int start_advertising(const char *name)
{
    struct ble_gap_adv_params advp;
    memset(&advp, 0, sizeof(advp));
    advp.conn_mode = BLE_GAP_CONN_MODE_UND;
    advp.disc_mode = BLE_GAP_DISC_MODE_GEN;

    ble_uuid16_t svc = {.u = {.type = BLE_UUID_TYPE_16}, .value = UUID16_HID_SERVICE};
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.appearance = APPEARANCE_MOUSE;
    fields.appearance_is_present = 1;
    fields.name = (uint8_t *)name;
    fields.name_len = strlen(name);
    fields.name_is_complete = 1;
    fields.uuids16 = &svc;
    fields.num_uuids16 = 1;
    fields.uuids16_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0)
    {
        ESP_LOGE(TAG, "ble_gap_adv_set_fields failed: %d", rc);
        return rc;
    }

    rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER, &advp, gap_event, NULL);
    if (rc != 0)
    {
        ESP_LOGE(TAG, "ble_gap_adv_start failed: %d", rc);
    }

    return rc;
}

static void notify_value(uint16_t attr_handle, const void *data, size_t len)
{
    if (!s_ble_connected || s_conn_handle == BLE_HS_CONN_HANDLE_NONE)
    {
        return;
    }
    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, len);
    if (!om)
    {
        ESP_LOGW(TAG, "notify_value: ble_hs_mbuf_from_flat failed");
        return;
    }
    int rc = ble_gatts_notify_custom(s_conn_handle, attr_handle, om);
    if (rc != 0)
    {
        ESP_LOGW(TAG, "notify_value: ble_gatts_notify_custom -> %d", rc);
        os_mbuf_free_chain(om);
    }
}

static void on_sync(void)
{
    int rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    if (rc != 0)
    {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto failed: %d", rc);
        return;
    }
    const char *name = s_device_name ? s_device_name : "uHID";
    /* Initialize GAP/GATT services and add our GATT services after the host is up */
    ble_svc_gap_init();
    ble_svc_gatt_init();
    ble_svc_gap_device_name_set(name);
    ble_svc_gap_device_appearance_set(APPEARANCE_MOUSE);
    ble_gatts_count_cfg(gatt_svcs);
    rc = ble_gatts_add_svcs(gatt_svcs);
    ESP_LOGI(TAG, "ble_gatts_add_svcs -> %d", rc);

    /* Start advertising */
    start_advertising(name);
}

// Host task runs in its own FreeRTOS task created by nimble_port_freertos_init.
static void host_task(void *pvParameters)
{
    (void)pvParameters;
    /* Host task runs the NimBLE event loop. sync_cb should already be set before this task starts. */

    nimble_port_run();

    /* Cleanly tear down the NimBLE port if the task exits. */
    nimble_port_freertos_deinit();
    nimble_port_deinit();
    s_nimble_ready = false;
    vTaskDelete(NULL);
}

void ble_hid_start(const char *name)
{
    // save name for the host task and start NimBLE
    s_device_name = name;
    /* Ensure the sync callback and security configuration are registered before the host starts */
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_NO_INPUT_OUTPUT;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID | BLE_SM_PAIR_KEY_DIST_SIGN;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID | BLE_SM_PAIR_KEY_DIST_SIGN;

    esp_err_t rc = nimble_port_init();
    if (rc != ESP_OK)
    {
        ESP_LOGE(TAG, "nimble_port_init failed: %d", rc);
        s_nimble_ready = false;
        return;
    }

    ble_store_config_init();

    s_nimble_ready = true;
    nimble_port_freertos_init(host_task);
}

static void ensure_security(uint16_t conn_handle)
{
    int sec_rc = ble_gap_security_initiate(conn_handle);
    if (sec_rc == BLE_HS_EALREADY || sec_rc == BLE_HS_EBUSY)
    {
        return;
    }
    if (sec_rc != 0)
    {
        ESP_LOGW(TAG, "ble_gap_security_initiate(%u) failed: %d", conn_handle, sec_rc);
    }
}

static void log_conn_security(uint16_t conn_handle, const char *context)
{
    struct ble_gap_conn_desc desc;
    if (ble_gap_conn_find(conn_handle, &desc) != 0)
    {
        return;
    }

    ESP_LOGI(TAG,
             "Security (%s): enc=%d auth=%d bonded=%d key_size=%u",
             context ? context : "",
             desc.sec_state.encrypted,
             desc.sec_state.authenticated,
             desc.sec_state.bonded,
             desc.sec_state.key_size);
}

void ble_hid_restart_advertising(void)
{
    const char *name = s_device_name ? s_device_name : "uHID";
    ble_svc_gap_device_name_set(name);
    int rc = start_advertising(name);
    if (rc != 0)
    {
        ESP_LOGW(TAG, "Failed to restart advertising: %d", rc);
    }
}

void ble_hid_notify_mouse(int8_t dx, int8_t dy, int8_t wheel, uint8_t buttons)
{
    s_mouse_state[0] = buttons;
    s_mouse_state[1] = dx;
    s_mouse_state[2] = dy;
    s_mouse_state[3] = wheel;
    if (h_mouse_rep)
    {
        ble_gatts_chr_updated(h_mouse_rep);
        notify_value(h_mouse_rep, s_mouse_state, sizeof(s_mouse_state));
    }
}

void ble_hid_kbd_set(uint8_t modifiers, const uint8_t keys[6])
{
    s_kbd_in[0] = modifiers;
    s_kbd_in[1] = 0;
    for (int i = 0; i < 6; i++)
        s_kbd_in[2 + i] = keys ? keys[i] : 0;
}

void ble_hid_notify_kbd(void)
{
    if (h_kbd_in)
    {
        ble_gatts_chr_updated(h_kbd_in);
        notify_value(h_kbd_in, s_kbd_in, sizeof(s_kbd_in));
    }
}

void ble_hid_notify_consumer(uint16_t usage)
{
    s_consumer_state[0] = usage & 0xFF;
    s_consumer_state[1] = (usage >> 8) & 0xFF;
    if (h_consumer_in)
    {
        ble_gatts_chr_updated(h_consumer_in);
        notify_value(h_consumer_in, s_consumer_state, sizeof(s_consumer_state));
    }
}

void ble_hid_set_battery(uint8_t pct)
{
    s_batt = pct;
    if (h_batt)
    {
        ble_gatts_chr_updated(h_batt);
        notify_value(h_batt, &s_batt, sizeof(s_batt));
    }
}

struct peer_iter_ctx
{
    ble_hid_peer_info_t *out;
    size_t max_out;
    size_t count;
    ble_addr_t *seen;
    size_t cap;
    int rc;
};

static int peer_iter_cb(int obj_type, union ble_store_value *val, void *cookie)
{
    struct peer_iter_ctx *ctx = (struct peer_iter_ctx *)cookie;
    if (!ctx)
    {
        return 0;
    }
    if (ctx->rc != 0)
    {
        return 1;
    }
    if (obj_type != BLE_STORE_OBJ_TYPE_PEER_SEC)
    {
        return 0;
    }

    ble_addr_t *addr = &val->sec.peer_addr;
    for (size_t i = 0; i < ctx->count; ++i)
    {
        if (ctx->seen[i].type == addr->type && memcmp(ctx->seen[i].val, addr->val, sizeof(addr->val)) == 0)
        {
            return 0;
        }
    }

    if (ctx->count >= ctx->cap)
    {
        size_t new_cap = ctx->cap ? ctx->cap * 2 : 4;
        ble_addr_t *tmp = (ble_addr_t *)realloc(ctx->seen, new_cap * sizeof(*tmp));
        if (!tmp)
        {
            ctx->rc = BLE_HS_ENOMEM;
            return 1;
        }
        ctx->seen = tmp;
        ctx->cap = new_cap;
    }

    size_t idx = ctx->count;
    ctx->seen[idx] = *addr;

    if (ctx->out && idx < ctx->max_out)
    {
        ble_hid_peer_info_t *info = &ctx->out[idx];
        info->addr_type = addr->type;
        memcpy(info->addr, addr->val, sizeof(info->addr));
        info->name[0] = '\0';
        info->connected = false;
        if (s_connected_peer_valid && s_connected_peer.type == addr->type &&
            memcmp(s_connected_peer.val, addr->val, sizeof(addr->val)) == 0)
        {
            info->connected = true;
        }
    }

    ctx->count++;
    return 0;
}

size_t ble_hid_get_bonded_peers(ble_hid_peer_info_t *peers, size_t max_peers)
{
    struct peer_iter_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.out = peers;
    ctx.max_out = max_peers;
    ctx.rc = 0;

    int rc = ble_store_iterate(BLE_STORE_OBJ_TYPE_PEER_SEC, peer_iter_cb, &ctx);
    if (rc != 0 && ctx.rc == 0)
    {
        ctx.rc = rc;
    }
    if (ctx.rc != 0)
    {
        ESP_LOGW(TAG, "ble_hid_get_bonded_peers: iterate rc=%d", ctx.rc);
    }

    if (ctx.seen)
    {
        free(ctx.seen);
    }

    return ctx.count;
}

bool ble_hid_forget_peer(uint8_t addr_type, const uint8_t addr[6])
{
    if (!addr)
    {
        return false;
    }
    ble_addr_t peer = {0};
    peer.type = addr_type;
    memcpy(peer.val, addr, sizeof(peer.val));
    int rc = ble_store_util_delete_peer(&peer);
    if (rc != 0)
    {
        ESP_LOGW(TAG, "ble_store_util_delete_peer failed: %d", rc);
        return false;
    }
    return true;
}

void ble_hid_set_kbd_out_callback(kbd_out_cb_t cb) { s_kbd_cb = cb; }

int ble_hid_get_bonded_count(void)
{
    if (!s_nimble_ready || esp_bt_controller_get_status() != ESP_BT_CONTROLLER_STATUS_ENABLED)
    {
        return 0;
    }
    size_t count = ble_hid_get_bonded_peers(NULL, 0);
    if (count > INT_MAX)
    {
        count = INT_MAX;
    }
    return (int)count;
}

int ble_hid_clear_bonded_peers(void)
{
    if (!s_nimble_ready || esp_bt_controller_get_status() != ESP_BT_CONTROLLER_STATUS_ENABLED)
    {
        return BLE_HS_EINVAL;
    }
    size_t count = ble_hid_get_bonded_peers(NULL, 0);
    if (count == 0)
    {
        return 0;
    }

    ble_hid_peer_info_t *peers = (ble_hid_peer_info_t *)calloc(count, sizeof(ble_hid_peer_info_t));
    if (!peers)
    {
        return BLE_HS_ENOMEM;
    }

    size_t filled = ble_hid_get_bonded_peers(peers, count);
    int rc = 0;
    for (size_t i = 0; i < filled; ++i)
    {
        if (!ble_hid_forget_peer(peers[i].addr_type, peers[i].addr))
        {
            rc = BLE_HS_EUNKNOWN;
        }
    }
    free(peers);
    return rc;
}

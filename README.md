# ESP32 BLE HID + Wi‑Fi Provisioning + UART Bridge

Composite BLE HID (Mouse + Keyboard) device on ESP‑IDF with:
- **Exact HID Report Descriptors** matching your MicroPython examples (Mouse RID=1, Keyboard RID=2).
- **Battery Service** (0x180F).
- **Wi‑Fi STA with AP fallback** provisioning and a minimalist **HTTP + WebSocket** server.
- **UART JSON protocol** to drive HID reports and toggle features.

Tested target: **ESP32‑WROOM** modules, ESP‑IDF **v6.0+** with NimBLE enabled.

> Upgrading from ESP‑IDF 5.x? Remove any cached build files (`idf.py fullclean`)
> and regenerate the project metadata with `idf.py reconfigure` so the 6.0
> toolchain can rebuild the CMake cache and component registry cleanly.

## Build

Before running any `idf.py` commands, make sure the ESP-IDF environment is exported:

```bash
. $IDF_PATH/export.sh   # or source /path/to/esp-idf/export.sh
idf.py set-target esp32
idf.py build flash monitor
```

> Requires: `CONFIG_BT_NIMBLE_*` enabled (see `sdkconfig.defaults`).

## Runtime

- On boot we try STA connect using stored creds. If it fails in ~6s, we start **SoftAP** (`ESP32-HID-Setup`) and serve the provisioning UI at `http://192.168.4.1/` (default password `uhid1234`).
- The UI exposes:
  - `GET /scan` → JSON list of `{ssid, rssi}`
  - `POST /configure` with JSON `{ssid,password}` → `OK`/`FAIL`
  - `GET /ws` → WebSocket echo
- The BLE device advertises as **uHID**, **appearance=962**, with **HID service 0x1812** and your report maps. Works with iOS HOGP hosts.

### Web dashboard tips

- The **Wi‑Fi setup** card keeps the network picker and password entry together so you can scan, pick an SSID, and immediately hit **Connect**.
- The **Bluetooth HID & tests** card shows BLE status, UART activity, and the WebSocket connection. Use the **Send test** button to push a sample mouse jiggle or keyboard tap; acknowledgements from the ESP32 appear in the log panel.

## UART Protocol (default enabled)

- Port: `UART0` @ 115200 8N1 (USB serial).
- Newline‑delimited JSON commands:

```json
{"type":"mouse","dx":10,"dy":-5,"wheel":0,"b1":1,"b2":0,"b3":0}
{"type":"key","mods":2,"keys":[0x04,0,0,0,0,0]}
{"type":"battery","pct":50}
{"type":"config","wifi":true,"web":true,"uart":true}
```

On start-up the bridge emits `{"type":"status","event":"ready"}` so hosts can
confirm the connection is open.

### Testing with `tools/uart_client.py`

1. Install [`pyserial`](https://pypi.org/project/pyserial/): `python3 -m pip install --user pyserial` (on Windows use the ESP-IDF Python environment prompt).
2. Connect the ESP32 USB serial bridge and note the device path (e.g. `/dev/ttyUSB0` on Linux/macOS or `COM3` on Windows).
3. Run a command, adding `--port` when auto-detect is insufficient:

   ```bash
   # Linux/macOS (auto-selects first /dev/ttyUSB*)
   python3 tools/uart_client.py mouse 40 -10 0 --b1 1

   # Windows example specifying COM3
   python tools/uart_client.py --port COM3 key --mods 0x02 0x04
   ```

4. Append `--listen` to leave the connection open and print reports from the firmware.

### Manual boot-protocol verification

Use these steps after flashing to confirm the boot mouse flow on iOS (last verified with iOS 17.5):

1. Pair the ESP32 from **Settings → Bluetooth** and connect as usual.
2. In **Settings → Accessibility → Touch → AssistiveTouch → Devices**, select the ESP32 and toggle **Use Mouse Keys** off/on to force the host into boot protocol mode.
3. Drag on the touchpad area—only XY movement and button clicks should register; scroll events are intentionally suppressed in boot mode.
4. Return to the AssistiveTouch device screen and toggle back to the normal profile; scroll and consumer keys resume once the host re-selects report protocol mode.

These steps exercise the protocol switch and ensure the reduced three-byte boot mouse report is accepted by iOS.

## UART CLI helper

- Requires Python 3 with [`pyserial`](https://pypi.org/project/pyserial/):

  ```bash
  python3 -m pip install --user pyserial
  ```

- Example invocations (defaults to the first `/dev/ttyUSB*` port):

  ```bash
  # Send a mouse move with button 1 held down
  python3 tools/uart_client.py mouse 40 -10 0 --b1 1

  # Press (and auto-release) Left-Shift + "a"
  python3 tools/uart_client.py key --mods 0x02 0x04

  # Update battery percentage
  python3 tools/uart_client.py battery 75

  # Toggle features
  python3 tools/uart_client.py config --wifi on --web off

  # Only listen/monitor bridge messages
  python3 tools/uart_client.py listen
  ```

Use `--port` to target a specific device and `--no-wait` to skip waiting for
the ready status message.

## API/Code Map

- `main/ble_hid.c` — NimBLE GATT server with:
  - **HID Info (2A4A), Report Map (2A4B), Control Point (2A4C), Report (2A4D), Protocol Mode (2A4E)** per service,
  - **Report Reference descriptor (2908)** set to `(RID, type)` → Mouse `(1, INPUT)`, Keyboard IN `(2, INPUT)`, OUT `(2, OUTPUT)`.
  - Notify helpers: `ble_hid_notify_mouse()`, `ble_hid_kbd_set()`, `ble_hid_notify_kbd()`, `ble_hid_set_battery()`.

- `main/wifi_mgr.cpp` — STA first, AP fallback; `wifi_scan()` for `/scan`.

- `main/http_server.cpp` — Routes `/`, `/scan`, `/configure`, `/ws` (WebSocket echo). `index.html` is embedded via `EMBED_FILES`.

- `main/uart_bridge.cpp` — JSON line parser driving BLE.

- `main/config_store.cpp` — simple NVS store for **feature toggles** and last SSID.

## Extending

- To mirror your MicroPython LED behavior, hook keyboard OUT report callback with `ble_hid_set_kbd_out_callback()` and drive a GPIO.
- To gate features from the web/API, add endpoints and call `cfg_save_toggles()` to persist.

## Notes & References

- esp_http_server and WebSocket usage: [ESP-IDF HTTP Server documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/protocols/esp_http_server.html#websocket-server).
- NimBLE GATT server patterns and characteristic updates: [ESP-IDF NimBLE GATT Server Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/bluetooth/nimble/nimble-gatt.html).
- ESP-IDF HID device APIs and HOGP background: [ESP HID Device API Reference](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/bluetooth/esp_hid.html).
- Wi-Fi STA/AP provisioning and SoftAP fallback: [ESP-IDF Wi-Fi Station + SoftAP Example](https://github.com/espressif/esp-idf/tree/v6.0/examples/wifi/getting_started/softAP).
- UART driver installation and event handling: [ESP-IDF UART Driver documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/peripherals/uart.html).

---

**License:** MIT for project scaffolding. Your HID descriptors are included verbatim.

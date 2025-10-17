# Code Review: ble-hid-combo-esp32

## Summary
This review covers the current ESP-IDF project that combines Wi-Fi provisioning, a BLE HID peripheral, a UART bridge, and a web UI. The following sections highlight functional gaps against the requested behaviour, correctness issues, and opportunities for improvement.

## Major Functional Gaps
- **Access point security and lifecycle** – The fallback AP is configured as an open network rather than enforcing the required default password `uhid1234`, leaving the device unsecured during provisioning. 【F:main/wifi_mgr.cpp†L122-L148】
- **AP to STA transition UX** – After a successful STA connection, the web UI only shows a static “connected” message and never refreshes to the new IP address or confirm closure of the AP. There is also no logic to redirect the browser once the AP interface shuts down. 【F:web/index.html†L153-L170】【F:main/http_server.cpp†L190-L218】
- **Device status in web UI** – The status endpoint and UI surface only minimal Wi-Fi information. There is no display of the hostname, connected stations, BLE peer list, or UART connection state that the requirements call for. 【F:main/http_server.cpp†L131-L170】【F:web/index.html†L72-L170】
- **BLE bonded device management** – Only the bonded count is exposed with a “forget all” button. There is no way to enumerate bonded peers, show connection status, or selectively remove a device. 【F:main/http_server.cpp†L172-L218】【F:web/index.html†L200-L223】
- **UART bridge visibility** – The firmware never reports whether the UART bridge task is running or if a host is attached, and the web UI has no client-side tooling to exchange messages with a Raspberry Pi. 【F:main/uart_bridge.cpp†L1-L88】【F:web/index.html†L72-L223】

## Correctness / Reliability Issues
- **BLE host task never runs** – The NimBLE host loop is replaced with a `while (1)` delay, so GAP/GATT events are never processed. This prevents reliable advertising, bonding, or reconnection. The host task must call `nimble_port_run()` and clean up on exit. 【F:main/ble_hid.c†L267-L301】
- **Missing bond storage configuration** – `ble_store_config_init()` is never called, so bonded keys are not persisted. This explains why iOS only reconnects after the device is forgotten. Persistent key storage is required for automatic reconnection. 【F:main/ble_hid.c†L245-L301】
- **BLE security defaults** – The stack never configures authentication requirements (e.g., `ble_hs_cfg.sm_io_cap`, bonding flags, or MITM). Without appropriate settings, iOS may refuse to treat the peripheral as a trusted pointer device. 【F:main/ble_hid.c†L245-L301】
- **Wi-Fi credential threshold** – STA connections are forced to require WPA2/WPA3 (`authmode` threshold), which prevents connecting to open or WEP networks—even though the UI permits selecting them. 【F:main/wifi_mgr.cpp†L90-L119】
- **Concurrent scan guard** – `wifi_scan_safe()` silently returns an empty list whenever the AP is running, so the web UI cannot show available networks while the fallback AP is active. A better approach is to keep the AP alive with AP+STA mode during the scan. 【F:main/wifi_mgr.cpp†L180-L185】
- **AP shutdown race** – `wifi_ap_stop()` can be invoked from the IP event handler while `http_server_stop()` is already running (during AP->STA transition), but the code does not guard against multiple calls or reset `s_ap_running`. This can leave the AP flag stale. 【F:main/wifi_mgr.cpp†L56-L176】

## Missing Features vs. Requirements
- **Hostname and IP reporting** – Neither the firmware nor UI exposes the ESP32 hostname or per-interface MAC addresses. 【F:main/http_server.cpp†L131-L170】【F:web/index.html†L72-L170】
- **Connected station enumeration** – There is no call to `esp_wifi_ap_get_sta_list()` to list Wi-Fi clients connected in AP mode. 【F:main/http_server.cpp†L131-L218】
- **BLE device list and “forget” control** – The firmware lacks an API to enumerate bonded peers (address/name) and remove them individually, which is needed for manual management. 【F:main/http_server.cpp†L172-L218】
- **Network persistence UX** – `cfg_set_last_ssid()` stores the last SSID, but it is never read back to pre-select the network when the page loads. 【F:main/config_store.cpp†L33-L48】【F:web/index.html†L90-L170】
- **UART client tooling** – No sample client script or protocol documentation is included for the Raspberry Pi side. 【F:main/uart_bridge.cpp†L1-L88】

## Additional Improvements
- **Expose scan progress** – Consider streaming scan progress/results over WebSocket instead of polling to reduce latency. 【F:web/index.html†L190-L224】
- **Error reporting** – Many ESP-IDF calls ignore return values (e.g., `esp_event_loop_create_default`, `esp_wifi_set_mode`). Checking and logging failures would simplify debugging. 【F:main/wifi_mgr.cpp†L70-L176】
- **Resource cleanup** – `wifi_scan_task` never clears `s_scan_task` or deletes the semaphore when stopping, which can leak handles over time. 【F:main/wifi_mgr.cpp†L180-L218】
- **HTTP server robustness** – The WebSocket handler allocates up to 4 kB per message without upper bounds on concurrent clients; consider limiting clients or reusing buffers. 【F:main/http_server.cpp†L190-L218】
- **Web UI polish** – The page is static HTML/JS; bundling it with a lightweight framework or at least separating logic could simplify additions like status banners and dynamic redirects. 【F:web/index.html†L57-L225】

## Suggested Next Steps
1. Fix the BLE host loop, configure security/bond storage, and verify pointer-mode interoperability with iOS accessibility.
2. Harden Wi-Fi provisioning: secure the AP, support AP+STA scanning, and add explicit success/failure callbacks that update the UI and redirect once STA is active.
3. Extend the HTTP API and UI to report detailed status (hostname, interface IPs, connected clients, BLE peers, UART health) and allow per-device management.
4. Provide tooling and documentation for the UART bridge protocol, including a reference Python script for the Raspberry Pi.
5. Add automated tests or integration scripts where possible (e.g., unit tests for config persistence, Web UI lint/build steps) to catch regressions.


idf_component_register(
    SRCS
        "app_main.cpp"
        "wifi_mgr.cpp"
        "http_server.cpp"
        "uart_bridge.cpp"
        "ble_hid.c"
        "config_store.cpp"
    INCLUDE_DIRS "."
    EMBED_FILES
        "../web/index.html"
    REQUIRES
        esp_http_server nvs_flash esp_wifi esp_netif esp_event
        bt esp_timer json
    PRIV_REQUIRES
        esp_driver_uart esp_driver_gpio
)

#pragma once
void uart_bridge_start();
bool uart_bridge_has_seen_data();
bool uart_bridge_handle_json(const char* json_line);

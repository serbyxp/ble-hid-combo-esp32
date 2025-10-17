#pragma once
#include <stddef.h>
#include "esp_http_server.h"

esp_err_t http_server_start();
void http_server_stop();

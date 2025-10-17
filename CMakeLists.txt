cmake_minimum_required(VERSION 3.16)
set(PROJECT_NAME "esp32_blehid_wifi_bridge")

if(NOT DEFINED ENV{IDF_PATH} OR "$ENV{IDF_PATH}" STREQUAL "")
    message(FATAL_ERROR "ESP-IDF environment not initialized. Please source export.sh (e.g. '. $ENV{HOME}/esp/esp-idf/export.sh') before configuring this project.")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(${PROJECT_NAME})

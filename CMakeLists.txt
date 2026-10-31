cmake_minimum_required(VERSION 3.16)
# Firmware version shown in the UI, SSH banner and OTA package names.
set(PROJECT_VER "0.1.0")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(SerialPill)

# The component manager restores managed components on every reconfigure, so the SerialPill
# adjustments to wolfSSL/wolfSSH (RSA on ESP32-C3, ed25519 user keys, empty pty modes) are
# re-applied here, after project() and before anything is compiled.
execute_process(COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/tools/patch_wolfssl.py ${CMAKE_SOURCE_DIR}
                RESULT_VARIABLE patch_result)
if(NOT patch_result EQUAL 0)
    message(FATAL_ERROR "tools/patch_wolfssl.py failed")
endif()

idf_component_register(
    SRCS "main.c" "config.c" "users.c" "tacacs.c" "audit.c" "bridge.c" "wifi.c" "migrate.c"
         "ssh_server.c" "telnet_server.c" "usb_bridge.c" "ota.c" "web.c" "api.c" "tls_self.c"
    INCLUDE_DIRS "."
    EMBED_FILES "bootloader/bootloader-std.bin" "web/xterm.js.gz" "web/xterm.css.gz" "web/xterm-addon-fit.js.gz" "web/blades.min.css.gz"
    EMBED_TXTFILES "web/index.html" "shelly_ca.pem"
    REQUIRES esp_wifi esp_netif esp_event nvs_flash esp_http_server esp_https_server esp_http_client
             esp_partition app_update spi_flash driver esp_driver_uart esp_driver_usb_serial_jtag
             esp_driver_gpio mbedtls json esp_timer bootloader_support efuse esp_app_format lwip
)

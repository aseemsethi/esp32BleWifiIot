idf_component_register(
	SRCS "projectMain.c" "oled.c" "u8g2_esp32_hal.c" "smartconfig_main.c"
	"wifi_eraseconfig.c" "ble_main.c" "ble_peer.c" "ble_misc.c"
	"wifi_mqtt.c" "sniffer.c" "blink.c"
    INCLUDE_DIRS "."
    REQUIRES bt u8g2 nvs_flash esp_http_server mqtt spiffs json)
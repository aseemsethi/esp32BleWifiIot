#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"  // FOR EventGroupHandle_t
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
//#include "esp_event_loop.h"

#include "esp_event.h"
#include <nvs_flash.h>
#include "driver/gpio.h"
#include "esp_log.h"  // for ESP_LOGE
#include "esp_event.h"
#include "string.h"
#include "sdkconfig.h"
#include <errno.h>
#include <esp_http_server.h>
#include "esp_smartconfig.h"

#include "esp_spi_flash.h"
#include "esp_log.h"  // for ESP_LOGE
#define SSID_MAX_LEN 33

/* LED RED ON: ESP32 turned on
 * LED BLUE FAST BLINK: startup phase
 * LED BLUE ON: ESP32 connected to the wifi, but not to the MQTT broker
 * LED BLUE BLINK: ESP32 connected to the broker */

/* --- LED variables --- */
#define BLINK_GPIO 2 //LED pin definition
#define BLINK_MODE 0
#define ON_MODE 1
#define OFF_MODE 2
#define STARTUP_MODE 3


void task_test_SSD1306i2c(void *ignore);
void oledDisplay(int x, int y, char* str);
void oledClear(void);
void smartconfig_run_task(void*);
void smartconfig_event_handler(void* arg, esp_event_base_t event_base, 
                                int32_t event_id, void* event_data);
void wifi_eraseconfig(void);
void printDiags(void);
void ble_main(void);
void wifi_mqtt_start(void*);
void wifi_send_mqtt(char*);
void sniffer_task();
void dumb(unsigned char *data, int len);
void get_ssid(unsigned char *data, char ssid[SSID_MAX_LEN], uint8_t ssid_len);
int get_sn(unsigned char *data);
void get_ht_capabilites_info(unsigned char *data, char htci[5], int pkt_len, int ssid_len);
void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type);
void wifi_init_sta(void);
void blink_task(void *pvParameter);
void set_blink_led(int state);

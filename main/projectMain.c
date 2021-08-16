/* Hello World Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include "common.h"
extern bool ble_running;

int BLINK_TIME_ON = 5; //LED blink time init on
int BLINK_TIME_OFF = 1000; //LED blink time init off

static void event_handler(void* arg, esp_event_base_t event_base, 
                                int32_t event_id, void* event_data);

EventGroupHandle_t s_wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;
const int WIFI_FAIL_BIT = BIT1;
char gDevIP[60];
static TaskHandle_t xHandle_sniff = NULL;
static TaskHandle_t mqttHandle = NULL;
static TaskHandle_t xHandle_led = NULL;

wifi_config_t wifi_config = {
    .sta = {
        //.ssid = EXAMPLE_ESP_WIFI_SSID,
        //.password = EXAMPLE_ESP_WIFI_PASS,
        /* Setting a password implies station will connect to all security modes including WEP/WPA.
         * However these modes are deprecated and not advisable to be used. Incase your Access point
         * doesn't support WPA2, these mode can be enabled by commenting below line */
     .threshold.authmode = WIFI_AUTH_WPA2_PSK,

        .pmf_cfg = {
            .capable = true,
            .required = false
        },
    },
};
static const char *TAG = "ProjMain  ";

void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                ESP_EVENT_ANY_ID, &event_handler,
                                NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                IP_EVENT_STA_GOT_IP, &event_handler,
                                NULL, &instance_got_ip));
    ESP_ERROR_CHECK( esp_event_handler_register(SC_EVENT, 
                                ESP_EVENT_ANY_ID, &smartconfig_event_handler, NULL));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA)); // WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    /* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
     * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);

    /* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
     * happened. */
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to AP");
        printDiags();
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGI(TAG, "Failed to connect to AP");
    } else {
        ESP_LOGE(TAG, "wifi init sta - UNEXPECTED EVENT");
    }
    ESP_LOGI(TAG, "=========================================================================WIFI");
    /* The event will not be processed after unregister */
    //ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));
    //ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
    //vEventGroupDelete(s_wifi_event_group);
}

void app_main(void)
{
    printf("Hello world!\n");
    esp_log_level_set("wifi", ESP_LOG_WARN);
    esp_log_level_set("*", ESP_LOG_DEBUG); 

    /* Print chip information */
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    printf("This is %s chip with %d CPU core(s), WiFi%s%s, ",
            CONFIG_IDF_TARGET,
            chip_info.cores,
            (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
            (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "");

    printf("silicon revision %d, ", chip_info.revision);

    printf("%dMB %s flash\n", spi_flash_get_chip_size() / (1024 * 1024),
            (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");

    printf("Minimum free heap size: %d bytes\n", esp_get_minimum_free_heap_size());

    fflush(stdout);
    // This is the new U8g2 driver; works for inbuilt OLED on WEMOS TTGO
    task_test_SSD1306i2c(NULL);
    //Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
    wifi_init_sta();
    /* Block for 500ms. */
    TickType_t xDelay = 500 / portTICK_PERIOD_MS;
    vTaskDelay(xDelay);

    // file to setup an INTR to clear WiFi NVS storage
    // On standard ESP32:
    // Boot button is connected to GPIO0 and pressing that, erases the WiFi storage
    // data that contains username/password
    // Learnings from https://github.com/lucadentella/esp32-tutorial
    wifi_eraseconfig(); 
    vTaskDelay(2000 / portTICK_PERIOD_MS);

    int lvl=0;
    gpio_pad_select_gpio(22); // Boot button
    gpio_set_direction(22, GPIO_MODE_INPUT);
    gpio_config_t io_conf;
    io_conf.intr_type = GPIO_PIN_INTR_DISABLE;
    io_conf.mode = GPIO_MODE_INPUT;
    io_conf.pin_bit_mask = (1<<22);
    io_conf.pull_down_en = 1;
    io_conf.pull_up_en = 0;
    gpio_config(&io_conf);

    ESP_LOGI(TAG, "[!] Starting sniffing task...");
    xTaskCreate(&sniffer_task, "sniffer_task", 10000, NULL, 1, &xHandle_sniff);
    if(xHandle_sniff == NULL)
        ESP_LOGI(TAG, "Unable to create sniffing task............");

    ESP_LOGI(TAG, "[!] Starting blink task...");
    xTaskCreate(&blink_task, "blink_task", configMINIMAL_STACK_SIZE, NULL, 5, &xHandle_led);
    if(xHandle_led == NULL)
        ESP_LOGI(TAG, "Unable to create Blink task");

    //set_blink_led(STARTUP_MODE);

    while(1) {
        TickType_t xDelay = 500 / portTICK_PERIOD_MS;
        vTaskDelay(xDelay);
        
        lvl=gpio_get_level(22);
        if (lvl == 1) {
            printf("\n Boot button pressed - erase flash !!!");
            nvs_flash_erase();
        }
    }
}

static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    tcpip_adapter_ip_info_t ip_info;
    int i;

    //ESP_LOGI(TAG, "event_handler eventid: %d", event_id);
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG,"WIFI_EVENT_STA_START recvd");
        //ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_FLASH));  
        esp_err_t ret = esp_wifi_get_config(ESP_IF_WIFI_STA, &wifi_config);
        if (ret == ESP_OK) {
            printf("\n !! Config found in Flash");
            printf("\nSize of esp_wifi_config: %i", sizeof(wifi_config));
            if (strlen((char*)wifi_config.sta.ssid) == 0) {
                printf("\n But, SSID is NULL...start Smart Config");
                oledClear(); 
                oledDisplay(40, 30, "- Smart Cfg");
                xTaskCreate(smartconfig_run_task, "Smart Config Task", 3072, NULL, 1, NULL);
                return;
            }
            printf("\nStored SSID: %s", (char *)wifi_config.sta.ssid);
            //printf("\nStored PASSWORD: %s", (char*)wifi_config.sta.password); 
            ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
            esp_wifi_connect();
        } else {
            printf("\n !!!! No config found in Flash");
            ESP_LOGI(TAG, "!!!!!!!!! Station Start Handler - start smart config"); 
            xTaskCreate(smartconfig_run_task, "Smart Config Task", 3072, NULL, 1, NULL);
        }
        //esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG,"WIFI_EVENT_STA_DISCONNECTED recvd");
        oledClear();  oledDisplay(7, 10, "DisConnected:"); 
        set_blink_led(STARTUP_MODE);
        //set_blink_led(OFF_MODE);
        //if (s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
            esp_wifi_connect();
        //    s_retry_num++;
        //    ESP_LOGI(TAG, "retry connect to AP");
        //} else {
        //    xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        //}
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
        ESP_LOGI(TAG,"WIFI_EVENT_STA_CONNECTED recvd");
        oledClear(); 
        oledDisplay(7, 10, "Connected:"); oledDisplay(7, 25, (char *)wifi_config.sta.ssid);
        set_blink_led(ON_MODE);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ESP_ERROR_CHECK(tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &ip_info));
        oledClear(); 
        set_blink_led(ON_MODE);
        oledDisplay(7, 10, "Connected:"); oledDisplay(7, 25, (char *)(ip4addr_ntoa(&ip_info.ip)));
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        //ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        //s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        ESP_LOGI(TAG, "got ip:%s\n", ip4addr_ntoa((const struct ip4_addr*)&event->ip_info.ip));
        if (ble_running == false)
            ble_main();
        if (mqttHandle == NULL) {
            xTaskCreate(wifi_mqtt_start, "WiFi MQTTTask", 4096, NULL, 1, &mqttHandle);
        }
    }
}

void printDiags() {
    tcpip_adapter_ip_info_t ip_info;
    uint8_t l_Mac[6];

    esp_wifi_get_mac(ESP_IF_WIFI_STA, l_Mac);
    ESP_LOGI(TAG, "MAC Address: %02x:%02x:%02x:%02x:%02x:%02x", l_Mac[0], l_Mac[1], l_Mac[2], l_Mac[3], l_Mac[4], l_Mac[5]);

    ESP_ERROR_CHECK(tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &ip_info));
    ESP_LOGI(TAG, "IP Address:  %s", ip4addr_ntoa(&ip_info.ip));
    ESP_LOGI(TAG, "Subnet mask: %s", ip4addr_ntoa(&ip_info.netmask));
    ESP_LOGI(TAG, "Gateway:     %s", ip4addr_ntoa(&ip_info.gw));

    ESP_LOGI(TAG, "Free memory: %d bytes", esp_get_free_heap_size());
    ESP_LOGI(TAG, "IDF version: %s", esp_get_idf_version());
}

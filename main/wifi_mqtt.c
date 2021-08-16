#include "common.h"
#include "mqtt_client.h"
#include <time.h>
#include <sys/time.h>
#include "esp_sntp.h"

extern EventGroupHandle_t wifi_event_group;
extern const int CONNECTED_BIT;
char mqtt_topic[100];
extern int mqtt;
extern char gDevIP[];
bool timeSet = pdFALSE;

static const char *TAG = "wifi mqtt";
esp_mqtt_client_handle_t client;
extern char foundMacs[10][20];
extern int foundIndex;

static esp_err_t mqtt_event_handler(esp_mqtt_event_handle_t event)
{
    // esp_mqtt_client_handle_t client = event->client;
    // int msg_id;
    // your_context_t *context = event->context;
    int i;
    switch (event->event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
            //msg_id = esp_mqtt_client_subscribe(client, "/topic99", 0);
            //ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);
            ESP_LOGI(TAG, "Send MAC Addresses....................");
            for (i=0; i<foundIndex; i++) {
                wifi_send_mqtt(foundMacs[i]);
            }
            break;
        case MQTT_EVENT_DISCONNECTED:
            //ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
            break;

        case MQTT_EVENT_SUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
            //msg_id = esp_mqtt_client_publish(client, "/topic99", "Hello again", 0, 0, 0);
            //ESP_LOGI(TAG, "sent publish successful, msg_id=%d", msg_id);
            break;
        case MQTT_EVENT_UNSUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_PUBLISHED:
            ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_DATA:
            ESP_LOGI(TAG, "MQTT_EVENT_DATA");
            ESP_LOGI(TAG,"TOPIC=%.*s\r\n", event->topic_len, event->topic);
            ESP_LOGI(TAG,"DATA=%.*s\r\n", event->data_len, event->data);
            break;
        case MQTT_EVENT_ERROR:
            //ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
            break;
        case MQTT_EVENT_BEFORE_CONNECT:
        case MQTT_EVENT_DELETED:
        case MQTT_EVENT_ANY:
            //ESP_LOGI(TAG, "MQTT_EVENT_BEFORE_CONNECT");
            break;
    }
    return ESP_OK;
}

void wifi_send_mqtt(char* msg) {
    time_t now;
    struct tm timeinfo;
    char strftime_buf[64];
    char temp[200];

    strcpy(temp, msg);
    strcat(temp, " : ");

    time(&now);
    localtime_r(&now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    //ESP_LOGI(TAG, "The current date/time : %s", strftime_buf);
    strcat(temp, strftime_buf);

    strcat(temp, ":");
    strcat(temp, gDevIP); 
    strcat(temp, ":");

	int msg_id = esp_mqtt_client_publish(client, mqtt_topic, temp, 0, 0, 0);
	ESP_LOGI(TAG, "\nwifi_send_mqtt: MQTT Msg: %s : to %s , with id: %d !!!", 
						temp, mqtt_topic, msg_id);
}

// String is of format "Thu Aug  8 06:57:45 2019"
int getCurrentTime() {
        time_t now;
        struct tm timeinfo;
        char strftime_buf[64];
        time(&now);
        //setenv("TZ", "CST+18:30", 1);
        //tzset();
        localtime_r(&now, &timeinfo);
        strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
        ESP_LOGI(TAG, "The current date/time : %s", strftime_buf); 

        char* pch;
        pch = strtok (strftime_buf," ");
        pch = strtok (NULL, " ");
        pch = strtok (NULL, " ");
        pch = strtok (NULL, " ");
        int i = atoi(pch); 
        ESP_LOGI(TAG, "The current date/time in hours/int: %s/%d", pch,i); 
        return i;
}

void time_sync_notification_cb(struct timeval *tv) {
    ESP_LOGI(TAG, "Notification of a time synchronization event");
}

void wifi_mqtt_start(void* param) {
    char strftime_buf[64];

    const esp_mqtt_client_config_t mqtt_cfg = {
        .uri = "mqtt://mqtt.eclipseprojects.io/",
        .port = 1883,
        .event_handle = mqtt_event_handler,
        // .user_context = (void *)your_context
    };
    client = esp_mqtt_client_init(&mqtt_cfg);
    strcpy(mqtt_topic, "aseemsethi");

    ESP_ERROR_CHECK(esp_mqtt_client_start(client));
    ESP_LOGI(TAG,"\n wifi_mqtt_start: Wifi connected..starting MQTT");
    wifi_send_mqtt("WiFi is up...");
    if (timeSet == pdFALSE) {
        ESP_LOGI(TAG, "\n Trying to get time from NTP");
        timeSet = pdTRUE;

        sntp_setoperatingmode(SNTP_OPMODE_POLL);
        sntp_setservername(0, "pool.ntp.org");
        sntp_set_time_sync_notification_cb(time_sync_notification_cb);
        sntp_init();

        time_t now = 0;
        struct tm timeinfo = { 0 };
        int retry = 0;
        const int retry_count = 10;
        while (sntp_get_sync_status() == SNTP_SYNC_STATUS_RESET && ++retry < retry_count) {
            ESP_LOGI(TAG, "Waiting for system time to be set... (%d/%d)", retry, retry_count);
            vTaskDelay(2000 / portTICK_PERIOD_MS);
        }
        time(&now);
        //setenv("TZ", "CST+18:30", 1);
        setenv("TZ", "UTC-5:30", 1);
        tzset();
        localtime_r(&now, &timeinfo);
        strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
        ESP_LOGI(TAG, "The current date/time is: %s", strftime_buf);
    }
    // Sleep for 1 sec in a for ever loop.
    while(1) {
        TickType_t xDelay = 1000 / portTICK_PERIOD_MS;
        vTaskDelay(xDelay);
    }
}
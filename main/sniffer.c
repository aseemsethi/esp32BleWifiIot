#include "common.h"
#define CONFIG_CHANNEL 11
static const char *TAG = "Sniffer  ";
#define MD5_LEN (32+1) //length of md5 hash
char foundMacs[20][30];  // 1st is string number, and 2nd is string len
int foundIndex = 0;

typedef struct {
	int16_t fctl; //frame control
	int16_t duration; //duration id
	uint8_t da[6]; //receiver address
	uint8_t sa[6]; //sender address
	uint8_t bssid[6]; //filtering address
	int16_t seqctl; //sequence control
	unsigned char payload[]; //network data
} __attribute__((packed)) wifi_mgmt_hdr;

void wifi_sniffer_init()
{
	tcpip_adapter_init();

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg)); //allocate resource for WiFi driver

	const wifi_country_t wifi_country = {
			.cc = "CN",
			.schan = 1,
			.nchan = 13,
			.policy = WIFI_COUNTRY_POLICY_AUTO
	};
	ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country)); //set country for channel range [1, 13]
	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
	ESP_ERROR_CHECK(esp_wifi_start());

	const wifi_promiscuous_filter_t filt = {
			.filter_mask = WIFI_EVENT_MASK_AP_PROBEREQRECVED
	};
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filt)); //set filter mask
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler)); //callback function
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true)); //set 'true' the promiscuous mode

	esp_wifi_set_channel(CONFIG_CHANNEL, WIFI_SECOND_CHAN_NONE); //only set the primary channel
}

void sniffer_task()
{
	int i;
	int sleep_time = 20*1000; // 10 seconds
	ESP_LOGI(TAG, "[SNIFFER] Sniffer task created");
	vTaskDelay(sleep_time / portTICK_PERIOD_MS);

	while(true){
		ESP_ERROR_CHECK(esp_wifi_disconnect()); //disconnect the ESP32 WiFi station from the AP
		ESP_ERROR_CHECK(esp_wifi_stop()); //it stop station and free station control block
		//ESP_ERROR_CHECK(esp_wifi_deinit()); //free all resource allocated in esp_wifi_init and stop WiFi task
		wifi_sniffer_init();
		ESP_LOGI(TAG, "[SNIFFER] Sniffing");
		vTaskDelay(sleep_time / portTICK_PERIOD_MS);
		ESP_LOGI(TAG, "[SNIFFER] Sniffing stopped...");
		esp_wifi_set_promiscuous(false);
		esp_wifi_stop();
		//ESP_ERROR_CHECK(esp_wifi_deinit()); //free all resource allocated in esp_wifi_init and stop WiFi task

		ESP_LOGI(TAG, "Found %d MAC Addresses...........", foundIndex);
		for (i=0; i<foundIndex; i++) {
			ESP_LOGI(TAG, "%s", foundMacs[i]);
		}
		vTaskDelay(1*1000 / portTICK_PERIOD_MS);
    	//ESP_ERROR_CHECK(esp_netif_init());
    	//esp_netif_create_default_wifi_sta();
    	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA)); // WIFI_MODE_STA));
	    ESP_ERROR_CHECK(esp_wifi_start());
	    vTaskDelay(sleep_time*2 / portTICK_PERIOD_MS);
	}
}

IRAM_ATTR void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{
	int pkt_len, fc, sn=0;
	char ssid[SSID_MAX_LEN] = "\0", hash[MD5_LEN] = "\0", htci[5] = "\0";
	uint8_t ssid_len, i;
	time_t ts;
	char macStr[20], tmp[30];

	wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;
	wifi_mgmt_hdr *mgmt = (wifi_mgmt_hdr *)pkt->payload;

	fc = ntohs(mgmt->fctl);
	//ESP_LOGI(TAG, "sniffer callback...");  strlen(macstr) is 17.
	snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
       	mgmt->sa[0], mgmt->sa[1], mgmt->sa[2], 
       	mgmt->sa[3], mgmt->sa[4], mgmt->sa[5]);
	macStr[17] = '\0';
	ESP_LOGI(TAG, "Sniffed MAC String: %s", macStr);
	sprintf(tmp, "WiFi:%s\n", macStr);
	for (i =0; i<foundIndex; i++) {
		if (strcmp(tmp, foundMacs[i]) == 0) {
			ESP_LOGI(TAG, "Duplicate MAC - ignore"); return;
		}
	}
	strcpy(foundMacs[foundIndex], tmp); foundIndex++; 
	if (foundIndex == 20) foundIndex = 19;


	return;
	if((fc & 0xFF00) == 0x4000){ //only look for probe request packets
		time(&ts);

		ssid_len = pkt->payload[25];
		if(ssid_len > 0)
			get_ssid(pkt->payload, ssid, ssid_len);

		pkt_len = pkt->rx_ctrl.sig_len;
		//get_hash(pkt->payload, pkt_len-4, hash);

			ESP_LOGI(TAG, "Dump");
			dumb(pkt->payload, pkt_len);

		sn = get_sn(pkt->payload);

		get_ht_capabilites_info(pkt->payload, htci, pkt_len, ssid_len);

		ESP_LOGI(TAG, "ADDR=%02x:%02x:%02x:%02x:%02x:%02x, "
				"SSID=%s, "
				"TIMESTAMP=%d, "
				"HASH=%s, "
				"RSSI=%02d, "
				"SN=%d, "
				"HT CAP. INFO=%s",
				mgmt->sa[0], mgmt->sa[1], mgmt->sa[2], mgmt->sa[3], mgmt->sa[4], mgmt->sa[5],
				ssid,
				(int)ts,
				hash,
				pkt->rx_ctrl.rssi,
				sn,
				htci);

		//save_pkt_info(mgmt->sa, ssid, ts, hash, pkt->rx_ctrl.rssi, sn, htci);
	}
}

void get_ssid(unsigned char *data, char ssid[SSID_MAX_LEN], uint8_t ssid_len)
{
	int i, j;

	for(i=26, j=0; i<26+ssid_len; i++, j++){
		ssid[j] = data[i];
	}

	ssid[j] = '\0';
}

int get_sn(unsigned char *data)
{
	int sn;
    char num[5] = "\0";

	sprintf(num, "%02x%02x", data[22], data[23]);
    sscanf(num, "%x", &sn);

    return sn;
}

void get_ht_capabilites_info(unsigned char *data, char htci[5], int pkt_len, int ssid_len)
{
	int ht_start = 25+ssid_len+19;

	/* 1) data[ht_start-1] is the byte that says if HT Capabilities is present or not (tag length).
	 * 2) I need to check also that i'm not outside the payload: if HT Capabilities is not present in the packet,
	 * for this reason i'm considering the ht_start must be lower than the total length of the packet less the last 4 bytes of FCS */

	if(data[ht_start-1]>0 && ht_start<pkt_len-4){ //HT capabilities is present
		if(data[ht_start-4] == 1) //DSSS parameter is set -> need to shift of three bytes
			sprintf(htci, "%02x%02x", data[ht_start+3], data[ht_start+1+3]);
		else
			sprintf(htci, "%02x%02x", data[ht_start], data[ht_start+1]);
	}
}

void dumb(unsigned char *data, int len)
{
	unsigned char i, j, byte;

	for(i=0; i<len; i++){
		byte = data[i];
		printf("%02x ", data[i]);

		if(((i%16)==15) || (i==len-1)){
			for(j=0; j<15-(i%16); j++)
				printf(" ");
			printf("| ");
			for(j=(i-(i%16)); j<=i; j++){
				byte = data[j];
				if((byte>31) && (byte<127))
					printf("%c", byte);
				else
					printf(".");
			}
			printf("\n");
		}
	}
}

#include "common.h"
static int BLINK_TIME_ON = 5; //LED blink time init on
static int BLINK_TIME_OFF = 1000; //LED blink time init off

void blink_task(void *pvParameter)
{
    gpio_pad_select_gpio(BLINK_GPIO);

    /* Set the GPIO as a push/pull output */
    gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);

    while(true){
        /* Blink off (output low) */
        gpio_set_level(BLINK_GPIO, 0);
        vTaskDelay(BLINK_TIME_OFF / portTICK_PERIOD_MS);

        /* Blink on (output high) */
        gpio_set_level(BLINK_GPIO, 1);
        vTaskDelay(BLINK_TIME_ON / portTICK_PERIOD_MS);
    }
}

void set_blink_led(int state)
{
    switch(state){
        case BLINK_MODE: //blink
            BLINK_TIME_OFF = 1000;
            BLINK_TIME_ON = 1000;
            break;
        case ON_MODE: //always on
            BLINK_TIME_OFF = 5;
            BLINK_TIME_ON = 2000;
            break;
        case OFF_MODE: //always off
            BLINK_TIME_OFF = 2000;
            BLINK_TIME_ON = 5;
            break;
        case STARTUP_MODE: //fast blink
            BLINK_TIME_OFF = 100;
            BLINK_TIME_ON = 100;
            break;
        default:
            break;
    }
}
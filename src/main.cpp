/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/bluetooth/bluetooth.h>
#include "google_fhd.h"

/* 1000 msec = 1 sec */
#define SLEEP_TIME_MS   1000

/* The devicetree node identifier for the "led0" alias. */
#define LED0_NODE DT_ALIAS(led0)
#define BUTTON0_NODE DT_ALIAS(sw0)

/*
 * A build error on this line means your board is unsupported.
 * See the sample documentation for information on how to fix this.
 */
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED0_NODE, gpios);
static const struct gpio_dt_spec button = GPIO_DT_SPEC_GET(BUTTON0_NODE, gpios);

char *eik_string = "2ba7b1af37bb6606deb507fc13f4b9d4697e88c80c5165b56c2de4cfe15996e1";

GoogleFhd googleFhd;

int main(void)
{
	int ret;

	if(googleFhd.init() < 0){
		return 0;
	}

	if(googleFhd.setEIK(eik_string) < 0){
		return 0;
	}
	uint8_t new_eid[20];
	googleFhd.generate_eid_160(0, new_eid);
	char *eid_string;
	googleFhd.bytes_to_hex_string(new_eid, eid_string, sizeof(new_eid));

	if (!gpio_is_ready_dt(&led)) {
		return 0;
	}

	if(!gpio_is_ready_dt(&button)) {
		return 0;
	}

	ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		return 0;
	}

	ret = gpio_pin_configure_dt(&button, GPIO_INPUT);
	if (ret < 0) {
		return 0;
	}

	while (1) {
		if(gpio_pin_get_dt(&button)){

			ret = gpio_pin_toggle_dt(&led);
			if (ret < 0) {
				return 0;
			}
			while(gpio_pin_get_dt(&button));
		}
	}
	return 0;
}

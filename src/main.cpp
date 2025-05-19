/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/gatt.h>
#include "google_fhd.h"

/* 1000 msec = 1 sec */
#define SLEEP_TIME_MS   1000

/* Devicetree node identifiers */
#define LED0_NODE DT_ALIAS(led0)
#define BUTTON0_NODE DT_ALIAS(sw0)

/* GPIO specs */
static const struct gpio_dt_spec led    = GPIO_DT_SPEC_GET(LED0_NODE, gpios);
static const struct gpio_dt_spec button = GPIO_DT_SPEC_GET(BUTTON0_NODE, gpios);

/* EIK string */
static char *eik_string = "2ba7b1af37bb6606deb507fc13f4b9d4697e88c80c5165b56c2de4cfe15996e1";

/* Single 128-bit UUID (little-endian) */
#define MY_UUID_BYTES \
    BT_UUID_128_ENCODE(0x9cc97f6b, 0x23fe, 0x4930, 0x8f36, 0xf54460d63f57)

static const struct bt_uuid_128 my_uuid =
    BT_UUID_INIT_128(MY_UUID_BYTES);

static const uint8_t my_uuid_bytes[16] = { MY_UUID_BYTES };

/* Simple Notify payload */
static uint8_t notify_value[20] = { 0 };

/* GATT service: primary service + notify characteristic + CCCD */
BT_GATT_SERVICE_DEFINE(multiTag,
    BT_GATT_PRIMARY_SERVICE(&my_uuid.uuid),
    BT_GATT_CHARACTERISTIC(&my_uuid.uuid,
                           BT_GATT_CHRC_NOTIFY,
                           BT_GATT_PERM_NONE,
                           NULL, NULL, NULL),
    BT_GATT_CCC(NULL, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
);

GoogleFhd googleFhd;

int main(void)
{
    int err, ret;

    /* Initialize BLE subsystem */
    err = bt_enable(NULL);
    if (err) {
        printk("Bluetooth init failed (err %d)\n", err);
        return 0;
    }
    printk("Bluetooth initialized\n");

    /* Advertising parameters: connectable + name in scan response */
    static const struct bt_le_adv_param *adv_params = BT_LE_ADV_PARAM(
        BT_LE_ADV_OPT_CONN | BT_LE_ADV_OPT_USE_NAME,
        BT_GAP_ADV_FAST_INT_MIN_2,
        BT_GAP_ADV_FAST_INT_MAX_2,
        NULL
    );

    /* Advertising data: flags only */
    static const struct bt_data ad[] = {
        BT_DATA_BYTES(BT_DATA_FLAGS,
                      (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
        BT_DATA(BT_DATA_UUID128_ALL,
                my_uuid_bytes,
                sizeof(my_uuid_bytes)),
    };

    /* Scan-response data: full device name */
    static const struct bt_data sd[] = {
        BT_DATA(BT_DATA_NAME_COMPLETE,
                CONFIG_BT_DEVICE_NAME,
                sizeof(CONFIG_BT_DEVICE_NAME) - 1),
    };

    /* Start advertising */
    err = bt_le_adv_start(adv_params,
                          ad, ARRAY_SIZE(ad),
                          sd, ARRAY_SIZE(sd));
    if (err) {
        printk("Advertising failed to start (err %d)\n", err);
        return 0;
    }
    printk("Advertising successfully started\n");

    /* Initialize Google FHD and generate an EID */
    if (googleFhd.init() < 0) {
        printk("GoogleFhd init failed\n");
        return 0;
    }
    if (googleFhd.setEIK(eik_string) < 0) {
        printk("Set EIK failed\n");
        return 0;
    }
    uint8_t new_eid[20];
    googleFhd.generate_eid_160(0, new_eid);
    char eid_string[41];
    googleFhd.bytes_to_hex_string(new_eid, eid_string, sizeof(new_eid));

    /* Configure LEDs and buttons */
    if (!gpio_is_ready_dt(&led) || !gpio_is_ready_dt(&button)) {
        printk("GPIO not ready\n");
        return 0;
    }
    ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
    if (ret < 0) {
        printk("LED config failed\n");
        return 0;
    }
    ret = gpio_pin_configure_dt(&button, GPIO_INPUT);
    if (ret < 0) {
        printk("Button config failed\n");
        return 0;
    }

    /* Main loop: toggle LED on button press */
    while (1) {
        if (gpio_pin_get_dt(&button)) {
            gpio_pin_toggle_dt(&led);

			err = bt_gatt_notify(
				/* conn = */ nullptr,
				/* attr = */ &multiTag.attrs[1],
				/* data = */ notify_value,
				/* length = */ sizeof(notify_value)
			);
			
			notify_value[0]++;

			if (err) {
				printk("Notify failed (err %d)\n", err);
			} else {
				printk("Notification sent: %02x\n", notify_value[0]);
			}


            while (gpio_pin_get_dt(&button)) {
                k_sleep(K_MSEC(10));
            }
        }
        k_sleep(K_MSEC(10));
    }
}

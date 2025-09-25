/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/gatt.h>
#include "google_fhd.h"
#include "settings.h"

#define STORAGE_PARTITION   storage_partition
#define STORAGE_PARTITION_ID      FIXED_PARTITION_ID(STORAGE_PARTITION)

/* 1000 msec = 1 sec */
#define SLEEP_TIME_MS   1000

//#define DISABLE_BT

/* Devicetree node identifiers */
#define LED0_NODE DT_ALIAS(led0)
#define BUTTON0_NODE DT_ALIAS(sw0)

/* GPIO specs */
static const struct gpio_dt_spec led     = GPIO_DT_SPEC_GET(LED0_NODE, gpios);
static const struct gpio_dt_spec button = GPIO_DT_SPEC_GET(BUTTON0_NODE, gpios);

/* EIK string */
static char *eik_string = "131f666fcbd2912bed50b94ff72af165d3353ed1c853a98519fb8ebbc25abc56";

/* Single 128-bit UUID (little-endian) */
#define MY_UUID_BYTES \
    BT_UUID_128_ENCODE(0x9cc97f6b, 0x23fe, 0x4930, 0x8f36, 0xf54460d63f57)

static const struct bt_uuid_128 my_uuid =
    BT_UUID_INIT_128(MY_UUID_BYTES);

static const uint8_t my_uuid_bytes[16] = { MY_UUID_BYTES };

static struct bt_conn *current_conn = NULL;

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

/* Callback for connection events */
static void connected(struct bt_conn *conn, uint8_t err)
{
    if (err) {
        printk("Connection failed (err %u)\n", err);
        current_conn = NULL;
        return;
    }

    printk("Connected\n");
    current_conn = bt_conn_ref(conn); // Store reference to the connection
}

/* Callback for disconnection events */
static void disconnected(struct bt_conn *conn, uint8_t reason)
{
    printk("Disconnected (reason %u)\n", reason);
    if (current_conn) {
        current_conn = NULL;
    }
    sys_reboot(SYS_REBOOT_WARM);
}


// Connection callbacks struct
BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected = connected,
    .disconnected = disconnected,
};

int main(void)
{
    int err, ret;
    
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
    ret = gpio_pin_configure_dt(&button, GPIO_OUTPUT_ACTIVE);
    if (ret < 0) {
        printk("Button config failed\n");
        return 0;
    }

    gpio_pin_set_dt(&led, 0); // Turn on LED initially
    gpio_pin_set_dt(&button, 0); // Turn on Button LED initially

    /* Initialize BLE subsystem */
    err = bt_enable(NULL);
    if (err) {
        printk("Bluetooth init failed (err %d)\n", err);
        return 0;
    }
    printk("Bluetooth initialized\n");
    
    /* Initialize Google FHD and generate an EID */
    if (googleFhd.init() < 0) {
        printk("GoogleFhd init failed\n");
        return 0;
    }
    if (googleFhd.setEIK(eik_string) < 0) {
        printk("Set EIK failed\n");
        return 0;
    }
    if (settings.init() < 0) { // Initialize settings subsystem
        printk("Settings init failed\n");
        settings.set_eik(googleFhd.eik);
        settings.set_time(1);
    }

    int startTime = settings.get_time();
    int lastSettings = k_uptime_get() + settings.get_time();
    int lastSwitch = lastSettings-20000;
    while (1) {
        int now = k_uptime_get() + startTime;
        if (lastSettings + (120*1000) < now) {
            settings.set_time(now);
            lastSettings = now;
            now = k_uptime_get() + startTime;
        }

        googleFhd.loop(now);

        if (lastSwitch + (20*1000) < now) {
            lastSwitch = now;
            bt_le_adv_stop();
            err = bt_le_adv_start(&googleFhd.adv_param, googleFhd.adv_data, 2, NULL, 0);
        }
        k_sleep(K_SECONDS(10)); // Sleeps for 10 seconds in low power
    }
}
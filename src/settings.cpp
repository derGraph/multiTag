#include "settings.h"
#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>

// Global settings instance
Settings settings;

Settings::Settings() : timestamp(0)
{
    memset(eik, 0, sizeof(eik));
}

int Settings::init()
{
    int ret = settings_subsys_init();
    if (ret) {
        printk("Settings subsystem init failed: %d\n", ret);
        return ret;
    }
    
    // Load existing settings
    if (load_eik() < 0) {
        printk("Failed to load EIK\n");
        return -1;
    }
    if (load_time() < 0) {
        printk("Failed to load timestamp\n");
        return -1;
    }
    return 0;
}
int Settings::load_eik()
{
    size_t len = sizeof(eik);
    int ret = settings_load_one(EIK_KEY, eik, len);
    if (ret == len) {
        printk("EIK loaded from storage\n");
        return 0;
    } else {
        printk("EIK not found in storage, using defaults\n");
        memset(eik, 0, sizeof(eik));
        return -1; // Indicate that the EIK was not found
    }
}

int Settings::load_time()
{
    size_t len = sizeof(timestamp);
    int ret = settings_load_one(TIME_KEY, &timestamp, len);
    if (ret == len) {
        printk("Timestamp loaded from storage: %u\n", timestamp);
        return 0;
    } else {
        printk("Timestamp not found in storage, using default\n");
        timestamp = 0;
        return -1; // Indicate that the timestamp was not found
    }
}

int Settings::set_eik(const uint8_t* new_eik)
{
    if (new_eik == nullptr) {
        printk("Error: EIK pointer is null\n");
        return -1;
    }
    
    memcpy(eik, new_eik, sizeof(eik));
    
    int ret = settings_save_one(EIK_KEY, eik, sizeof(eik));
    if (ret) {
        printk("Failed to save EIK: %d\n", ret);
        return -1;
    } else {
        printk("EIK updated and saved\n");
        return 0;
    }
}

int Settings::get_eik(uint8_t* eik_out) const
{
    if (eik_out == nullptr) {
        printk("Error: Output EIK pointer is null\n");
        return -1;
    }
    
    memcpy(eik_out, eik, sizeof(eik));
    return 0;
}

int Settings::set_time(uint32_t new_time)
{
    timestamp = new_time;
    
    int ret = settings_save_one(TIME_KEY, &timestamp, sizeof(timestamp));
    if (ret) {
        printk("Failed to save timestamp: %d\n", ret);
        return -1;
    } else {
        printk("Timestamp set to: %u and saved\n", timestamp);
        return 0;
    }
}

uint32_t Settings::get_time() const
{
    return timestamp;
}

#include <cstdint>

class Settings {
private:
    uint8_t eik[32];
    uint32_t timestamp;
    
    // Settings keys
    static constexpr const char* EIK_KEY = "multiTag-eik";
    static constexpr const char* TIME_KEY = "multiTag-time";

    // Load data from settings storage
    int load_eik();
    int load_time();

public:
    Settings();
    
    // Initialize settings subsystem
    int init();
    
    // EIK management
    int set_eik(const uint8_t* new_eik);
    int get_eik(uint8_t* eik_out) const;
    
    // Timestamp management
    int set_time(uint32_t new_time);
    uint32_t get_time() const;
};

// Global instance
extern Settings settings;

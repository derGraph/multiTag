#ifndef GOOGLE_FHD_
#define GOOGLE_FHD_
struct fmdn_service_data_t {
    uint16_t service_uuid;
    uint8_t frame_type;
    uint8_t eid[20];
    uint8_t hashed_flags;
};

// Public function declaration
class GoogleFhd {
    public:
        GoogleFhd();
        uint8_t eik[32];
        uint8_t eid[20];
        static struct bt_le_adv_param adv_param;
        static struct bt_data adv_data[2];
        static struct fmdn_service_data_t fmdn_service_data;
        int init();
        int setEIK(char* hexStr);
        int generate_eid_160(uint32_t timestamp, uint8_t eid[20]);
        int hex_string_to_bytes(const char *hex, uint8_t *bytes, size_t len);
        void bytes_to_hex_string(const uint8_t *bytes, char *output, size_t len);
        void loop(int time);
    private:
        bool initialized;
        int lastLoop;
        static uint8_t hex_char_to_val(char c);
        uint8_t hexCharToUint(char c);
        int bignum_from_string(struct bn* n, char* str, int nbytes);
        int bignum_to_string(struct bn* n, char str[], int size);
        int bignum_from_bytes(struct bn* n, const uint8_t* bytes, int nbytes);
        int bignum_to_bytes(struct bn* n, uint8_t bytes[], int size);
};
#endif /* GOOGLE_FHD_ */
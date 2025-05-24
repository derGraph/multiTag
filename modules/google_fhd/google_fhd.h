#ifndef GOOGLE_FHD_
#define GOOGLE_FHD_

// Public function declaration
class GoogleFhd {
    public:
        GoogleFhd();
        uint8_t eik[32];
        int init();
        int setEIK(char* hexStr);
        int generate_eid_160(uint32_t timestamp, uint8_t eid[20]);
        int hex_string_to_bytes(const char *hex, uint8_t *bytes, size_t len);
        void bytes_to_hex_string(const uint8_t *bytes, char *output, size_t len);
    private:
        bool initialized;
        static uint8_t hex_char_to_val(char c);
        int compare_20be(const uint8_t* a, const uint8_t* b);
        void mod_reduce_160bit(const uint8_t* r_dash, uint8_t* r_mod);
        bool compute_eid_from_r_dash(const uint8_t* r_dash, uint8_t* eid_out);
};
#endif /* GOOGLE_FHD_ */
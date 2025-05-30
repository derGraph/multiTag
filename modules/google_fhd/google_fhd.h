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
        uint8_t hexCharToUint(char c);
        int bignum_from_string(struct bn* n, char* str, int nbytes);
        int bignum_to_string(struct bn* n, char str[], int size);
        int bignum_from_bytes(struct bn* n, const uint8_t* bytes, int nbytes);
};
#endif /* GOOGLE_FHD_ */
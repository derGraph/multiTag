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
    private:
        bool initialized;
        void hex_string_to_bytes(const char *hex, uint8_t *bytes, size_t len);
};
#endif /* GOOGLE_FHD_ */
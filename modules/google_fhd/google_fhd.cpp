#include <zephyr/kernel.h>
#include <string.h> 
#include <stdlib.h>
#include <stdio.h>
#include <zephyr/sys/byteorder.h>

extern "C" {
    #include "tfm.h"
}
#include "aes.hpp"

#include "uECC_vli.h"

#include "uECC.h"

#define ROTATION_EXPONENT 10
#define ROTATION_PERIOD (1 << ROTATION_EXPONENT)

#include "google_fhd.h"

GoogleFhd::GoogleFhd()
{
    initialized = false;
    return;
}

int GoogleFhd::init()
{   
    initialized = true;
    return 0;
}

int GoogleFhd::generate_eid_160(uint32_t timestamp, uint8_t eid[20]) {
    uint8_t input[32];
    uint8_t __aligned(4) r_dash[32];
    const struct uECC_Curve_t *curve = uECC_secp160r1();
    int num_bytes = uECC_curve_num_bytes(curve); // should be 20 bytes for SECP160R1
    struct AES_ctx ctx;

    // 1) Build the 32-byte AES input
    memset(input, 0xFF, 11);
    input[11] = ROTATION_EXPONENT;
    uint32_t rounded_ts = timestamp & ~(ROTATION_PERIOD - 1);
    input[12] = (rounded_ts >> 24) & 0xFF;
    input[13] = (rounded_ts >> 16) & 0xFF;
    input[14] = (rounded_ts >>  8) & 0xFF;
    input[15] = (rounded_ts >>  0) & 0xFF;
    memset(&input[16], 0x00, 11);
    input[27] = ROTATION_EXPONENT;
    input[28] = input[12];
    input[29] = input[13];
    input[30] = input[14];
    input[31] = input[15];

    // 2) Initialize AES context with 256-bit key
    AES_init_ctx(&ctx, eik);

    // 3) Encrypt two 16-byte blocks in ECB mode
    memcpy(r_dash +  0, input +  0, 16);
    AES_ECB_encrypt(&ctx, r_dash);
    memcpy(r_dash + 16, input + 16, 16);
    AES_ECB_encrypt(&ctx, r_dash + 16);

    //VALIDATED UNTIL HERE

    // Step 1: Convert r_dash (32 bytes) into a big integer using tomsfastmath
    fp_int r_dash_int, n, r;
    fp_init(&r_dash_int);
    fp_init(&n);
    fp_init(&r);


    //CRASHES HERE
    fp_read_unsigned_bin(&r_dash_int, (uint8_t *)r_dash, 32);

    // Step 2: Load the order of the curve (n)
    const uint8_t *curve_n = (const uint8_t *)uECC_curve_n(curve);
    fp_read_unsigned_bin(&n, (uint8_t *)curve_n, num_bytes);

    // Step 3: r = r_dash_int mod n
    fp_mod(&r_dash_int, &n, &r);

    // Step 4: Convert r (fp_int) to byte array for uECC (pad to num_bytes)
    uint8_t r_bytes[20] = {0};
    uint8_t tmp[20] = {0};
    int r_size = fp_unsigned_bin_size(&r);
    fp_to_unsigned_bin(&r, tmp);
    memcpy(&r_bytes[num_bytes - r_size], tmp, r_size); // left-pad

    // Step 5: Compute R = r * G
    uint8_t R[40]; // 2 * num_bytes
    uECC_compute_public_key(r_bytes, R, curve);

    // Step 6: Return x-coordinate (first 20 bytes)
    memcpy(eid, R, 20);
    return 0;
}

int GoogleFhd::hex_string_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        uint8_t high = hex_char_to_val(hex[2 * i]);
        uint8_t low  = hex_char_to_val(hex[2 * i + 1]);
        if (high == 0xFF || low == 0xFF) {
            return -1; // Invalid hex input
        }
        bytes[i] = (high << 4) | low;
    }
    return 0;
}

/* Convert 2 hex characters to a byte */
uint8_t GoogleFhd::hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0xFF; // Invalid
}

void GoogleFhd::bytes_to_hex_string(const uint8_t *bytes, char *output, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sprintf(output + i * 2, "%02x", bytes[i]);  // or "%02X" for uppercase hex
    }
    output[len * 2] = '\0';  // Null-terminate the string
}

int GoogleFhd::setEIK(char* hexStr) {

    if (strlen(hexStr) != 64) {
        return -1;
    }

    for (size_t i = 0; i < 32; ++i) {
        char byteStr[3] = { hexStr[i * 2], hexStr[i * 2 + 1], '\0' };
        eik[i] = (uint8_t)strtoul(byteStr, nullptr, 16);
    }

    return 0;
}

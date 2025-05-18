#include <zephyr/kernel.h>
#include <string.h> 
#include <stdlib.h>
#include <stdio.h>
#include <zephyr/sys/byteorder.h>

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
    uint8_t r_prime[32];
    uint8_t r_bytes[20];
    uint8_t pub[40];
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
    memcpy(r_prime +  0, input +  0, 16);
    AES_ECB_encrypt(&ctx, r_prime +  0);
    memcpy(r_prime + 16, input + 16, 16);
    AES_ECB_encrypt(&ctx, r_prime + 16);

    // 4) Reduce r_prime modulo the curve order n
    const struct uECC_Curve_t *curve = uECC_secp160r1();
    unsigned curve_bytes = uECC_curve_num_bytes(curve);
    uint32_t native[10] = {0};       // holds up to 320-bit value
    uint32_t n_native[10] = {0};

    uECC_vli_bytesToNative(native, r_prime, 32);
    uECC_vli_bytesToNative(n_native, (const uint8_t*)uECC_curve_n(curve), curve_bytes);
    uECC_vli_mmod(native, native, n_native, curve_bytes / sizeof(uint32_t));
    uECC_vli_nativeToBytes(r_bytes, curve_bytes, native);

    // 5) Compute EC point R = r * G
    if (!uECC_compute_public_key(r_bytes, pub, curve)) {
        return -1;
    }

    // 6) Copy X-coordinate as EID
    memcpy(eid, pub, curve_bytes);

    return 0;
}

void GoogleFhd::hex_string_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
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

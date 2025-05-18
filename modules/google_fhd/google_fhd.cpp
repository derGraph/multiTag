#include <zephyr/kernel.h>
#include <string.h> 
#include <stdlib.h>
#include <stdio.h>
#include <zephyr/sys/byteorder.h>

#include <psa/crypto.h>
#include <mbedtls/bignum.h>


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
    psa_status_t status = psa_crypto_init();
    if(status != PSA_SUCCESS){
        return -1;
    }

    initialized = true;
    return 0;
}

int GoogleFhd::generate_eid_160(uint32_t timestamp, uint8_t eid[20]) {
    // 1) Build the 32-byte AES input:
    //    Bytes 0-10: 0xFF
    //    Byte 11: rotation exponent K
    //    Bytes 12-15: rounded timestamp (big-endian), lower K bits zeroed
    //    Bytes 16-26: 0x00
    //    Byte 27: rotation exponent K
    //    Bytes 28-31: same rounded timestamp
    uint8_t input[32] = {0};
    memset(input, 0xFF, 11);
    input[11] = ROTATION_EXPONENT;
    uint32_t rounded_ts = timestamp & ~(ROTATION_PERIOD - 1);
    sys_put_be32(rounded_ts, &input[12]);
    memset(&input[16], 0x00, 11);
    input[27] = ROTATION_EXPONENT;
    sys_put_be32(rounded_ts, &input[28]);

    // 2) Import ephemeral identity key into PSA Crypto
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_ECB_NO_PADDING);
    psa_key_handle_t key_handle;
    psa_status_t status = psa_import_key(
        &attr,
        eik, sizeof(eik),
        &key_handle
    );
    if (status != PSA_SUCCESS) {
        return status;  // AES import failed
    }

    // 3) AES-ECB-256 encrypt input -> r_prime (32 bytes)
    uint8_t r_prime[32] = {0};
    size_t r_len = 0;
    status = psa_cipher_encrypt(
        key_handle,
        PSA_ALG_ECB_NO_PADDING,
        input, sizeof(input),
        r_prime, sizeof(r_prime), &r_len
    );
    psa_destroy_key(key_handle);
    if (status != PSA_SUCCESS || r_len != sizeof(r_prime)) {
        return status;  // Encryption failed
    }
    
    // 4) Interpret r_prime as big integer, reduce modulo curve order n
    mbedtls_mpi r_big, r_mod, n;
    mbedtls_mpi_init(&r_big);
    mbedtls_mpi_init(&r_mod);
    mbedtls_mpi_init(&n);
    
    const struct uECC_Curve_t* curve = uECC_secp160r1();
    size_t curve_bytes = uECC_curve_num_bytes(curve);  // should be 20

    // Load curve order n (160-bit) into an MPI
    uint8_t n_bytes[20] = {0};
    uECC_vli_nativeToBytes(n_bytes, curve_bytes, uECC_curve_n(curve));
    mbedtls_mpi_read_binary(&n, n_bytes, curve_bytes);

    // r_big = r_prime
    mbedtls_mpi_read_binary(&r_big, r_prime, sizeof(r_prime));
    // r_mod = r_big mod n
    mbedtls_mpi_mod_mpi(&r_mod, &r_big, &n);
    
    // 5) Convert reduced r to bytes (big-endian, curve_bytes long)
    uint8_t r_bytes[20] = {0};
    mbedtls_mpi_write_binary(&r_mod, r_bytes, curve_bytes);
    
    // 6) Compute EC point R = r * G
    uint8_t public_key[40] = {0};  // 2 * curve_bytes for X||Y
    if (!uECC_compute_public_key(r_bytes, public_key, curve)) {
        // cleanup
        mbedtls_mpi_free(&r_big);
        mbedtls_mpi_free(&r_mod);
        mbedtls_mpi_free(&n);
        return -1;
    }

    // 7) Copy X coordinate (first curve_bytes) as the EID
    memcpy(eid, public_key, curve_bytes);

    // cleanup MPIs
    mbedtls_mpi_free(&r_big);
    mbedtls_mpi_free(&r_mod);
    mbedtls_mpi_free(&n);

    return 0;  // success
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

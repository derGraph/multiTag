#include <zephyr/kernel.h>
#include <string.h> 
#include <stdlib.h>
#include <stdio.h>
#include <zephyr/sys/byteorder.h>

extern "C" {
    #include "bn.h"
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
    static uint8_t __aligned(4) r_dash[32];
    //const struct uECC_Curve_t *curve = uECC_secp160r1();
    //int num_bytes = uECC_curve_num_bytes(curve); // should be 20 bytes for SECP160R1
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

    // 4) Convert r_dash to bignum and compute r' mod n
    // Initialize bignum structures
    struct bn r_dash_bn;
    struct bn n_bn;
    struct bn r_bn;
    struct bn test_bn;

    bignum_init(&r_dash_bn);
    bignum_init(&n_bn);
    bignum_init(&r_bn);

    bignum_init(&test_bn);

    bignum_from_bytes(&r_dash_bn, r_dash, sizeof(r_dash)); // Convert r_dash to bignum

    // TRY TO GET N FROM uECC_secp160r1
    if(bignum_from_string(&n_bn, "0000000100000000000000000001f4c8f927aed3ca752257", 48) == -1){
        printk("Error converting n to bignum\n");
        return -1; // Error: failed to convert n to bignum
    }

    // Calculate r = r' mod n
    bignum_mod(&r_dash_bn, &n_bn, &r_bn);

    char r_hex[37];
    bignum_to_string(&r_bn, r_hex, sizeof(r_hex)/sizeof(r_hex[0]));
    printk("r = %s\n", r_hex);

    // VALIDATED UNTIL HERE

    //bignum_to_string(&result_bn, final_r_str, sizeof(final_r_str));
    //printk("r_dash_int %% n = %s\n", final_r_str);

    // Step 5: Compute R = r * G
    uint8_t R[40]; // 2 * num_bytes
    // COMPUTE R WITH BIGNUM LIBRARY THEN CONVERT WITH hex_string_to_bytes
    uint8_t r_bytes[21]; // 21 bytes for SECP160R1 private key
    const struct uECC_Curve_t *curve = uECC_secp160r1();
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

// Helper function to convert a single hex character to its integer value
uint8_t GoogleFhd::hexCharToUint(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    // Error handling: In Zephyr, you might use K_PANIC or printk and return an error code.
    // For this example, we'll return 0xFF to indicate an error.
    return 0xFF;
}

int GoogleFhd::bignum_from_string(struct bn* n, char* str, int nbytes){

    if(n==NULL){
        printk("bignum_from_string: n is NULL\n");
        return -1; // Error: null pointer
    }

    if(str==NULL){
        printk("bignum_from_string: str is NULL\n");
        return -1; // Error: null pointer
    }
    if(nbytes <= 0) {
        printk("bignum_from_string: nbytes must be positive\n");
        return -1; // Error: invalid size
    }
    if((nbytes & 1) != 0) {
        printk("bignum_from_string: string format must be in hex -> equal number of bytes\n");
        return -1; // Error: invalid format
    }
    if((nbytes % (sizeof(DTYPE) * 2)) != 0) {
        printk("bignum_from_string: string length must be a multiple of (sizeof(DTYPE) * 2) characters\n");
        return -1; // Error: invalid length
    }

    bignum_init(n);

    // Calculate starting index to read the last 'WORD_SIZE_HEX_CHARS' hex characters first.
    // We want to process the string from right to left, in chunks.
    int j = 0; // Index for resultBn->array

    // It's good practice to clear the array before populating,
    // especially if not all elements will be filled.
    // In a Zephyr environment, you might use memset.
    // (Note: This is a loop for clarity; memset would be faster)
    for (size_t k = 0; k < BN_ARRAY_SIZE; ++k) {
        n->array[k] = 0;
    }

    //RECHECK THIS LOOP, FIRST String WORD is not processed (last output)
    for(int a = nbytes - (2 * WORD_SIZE); a>=0; a-=(WORD_SIZE * 2)){
        DTYPE tmp = 0;
        for (int k = 0; k < (WORD_SIZE * 2); k++) {
            char current_char = str[a + k];
            uint8_t hex_val = hexCharToUint(current_char);

            if (hex_val == 0xFF) { // Error check for invalid hex character
                // In Zephyr, you'd log an error and possibly k_panic().
                printk("Error: Invalid hex character '%c' at index %d\n", current_char, a + k);
                return -1; // Abort on error
            }
            tmp = (tmp << 4) | hex_val; // Shift existing bits left by 4, then OR in new hex value
        }
        n->array[j] = tmp;
        j += 1;
    }
    return 0; // Successfully parsed the string into the bignum structure
}

int GoogleFhd::bignum_to_string(struct bn* n, char str[], int size){
    char temp[BN_ARRAY_SIZE*2*WORD_SIZE +1] = ""; // +1 for null terminator
    for(int i = BN_ARRAY_SIZE-1; i >= 0; i--) {
        char word[WORD_SIZE * 2 + 1]; // +1 for null terminator
        sprintf(word, "%08x", n->array[i]);
        strcat(temp, word);
    }
    int j = 0;
    char new_temp[BN_ARRAY_SIZE*2*WORD_SIZE +1] = ""; // +1 for null terminator
    for(int i = 0; i < (BN_ARRAY_SIZE * 2 * WORD_SIZE + 1); i++) {
        if(temp[i] != '0'){
            new_temp[j] = temp[i];
            j++;
        }
        if(temp[i] == '\000'){
            break; // Stop at the first null character
        }
    }
    if(strlen(new_temp)+1 > size) {
        printk("bignum_to_string: string size is too small\n");
        return -1; // Error: string size is too small
    }
    strcpy(str, new_temp);
    return 0;
}

int GoogleFhd::bignum_from_bytes(struct bn* n, const uint8_t* bytes, int nbytes) {

    if(n==NULL){
        printk("bignum_from_bytes: n is NULL\n");
        return -1; // Error: null pointer
    }

    if(bytes==NULL){
        printk("bignum_from_bytes: bytes is NULL\n");
        return -1; // Error: null pointer
    }
    if(nbytes <= 0) {
        printk("bignum_from_bytes: nbytes must be positive\n");
        return -1; // Error: invalid size
    }
    if((nbytes & 1) != 0) {
        printk("bignum_from_bytes: string format must be in hex -> equal number of bytes\n");
        return -1; // Error: invalid format
    }
    if((nbytes % (sizeof(DTYPE) * 2)) != 0) {
        printk("bignum_from_bytes: string length must be a multiple of (sizeof(DTYPE) * 2) characters\n");
        return -1; // Error: invalid length
    }

    bignum_init(n);

    // Calculate starting index to read the last 'WORD_SIZE_HEX_CHARS' hex characters first.
    // We want to process the string from right to left, in chunks.
    int j = 0; // Index for resultBn->array

    // It's good practice to clear the array before populating,
    // especially if not all elements will be filled.
    // In a Zephyr environment, you might use memset.
    // (Note: This is a loop for clarity; memset would be faster)
    for (size_t k = 0; k < BN_ARRAY_SIZE; ++k) {
        n->array[k] = 0;
    }

    for(int word = nbytes - WORD_SIZE; word >= 0; word -= WORD_SIZE) {
        DTYPE tmp = 0;
        for (int byte = 0; byte < WORD_SIZE; byte++) {
            //WORKING
            uint8_t hex_val = bytes[word + byte];
            tmp = (tmp << 8) | hex_val; // Shift existing bits left by 8, then OR in new hex value
        }
        n->array[j] = tmp;
        j += 1;
    }
    return 0; // Successfully parsed the string into the bignum structure
}

void check(bool condition, const char* message) {
    if (!condition) {
        printk("Error: %s\n", message);
    }
}
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* PSA Crypto core */
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_STORAGE_C

/* Entropy and DRBG (for PSA keys) */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_SHA256_C        /* For entropy’s default seed extractor */ 
#define MBEDTLS_CTR_DRBG_C

/* Cipher and AES (ECB) */
#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_ECB

/* MPI bignum support */
#define MBEDTLS_BIGNUM_C

/* Platform abstraction */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY

#endif /* MBEDTLS_CONFIG_H */

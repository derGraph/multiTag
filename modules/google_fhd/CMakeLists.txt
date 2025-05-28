if(CONFIG_GOOGLE_FHD)

    # Tell Zephyr this is a library
    zephyr_library()


    # Include paths
    zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR})
    zephyr_library_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/micro-ecc)
    zephyr_library_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/tiny-AES-c)
    zephyr_library_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/tiny-bignum-c)

    zephyr_library_compile_definitions(
        uECC_ENABLE_VLI_API=1
        uECC_SUPPORTS_secp256k1=0
        uECC_SUPPORTS_secp256r1=0
        uECC_SUPPORTS_secp224r1=0
        uECC_SUPPORTS_secp192r1=0
        uECC_OPTIMIZATION_LEVEL=0
        AES256=1
        ECB=1
        WORD_SIZE=4
    )

    # Add your main source file
    zephyr_library_sources(
        google_fhd.cpp
        micro-ecc/uECC.c
        tiny-AES-c/aes.c
        tiny-bignum-c/bn.c
    )
endif()

# Check if SAY_HELLO is set in Kconfig
if(CONFIG_GOOGLE_FHD)

    # Add your source file directory
    zephyr_include_directories(.)
    zephyr_include_directories(${ZEPHYR_BASE}/../modules/crypto/mbedtls/include)

    # Add the source file you want to compile
    zephyr_library_sources(google_fhd.cpp)

endif()
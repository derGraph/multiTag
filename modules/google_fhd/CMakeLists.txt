if(CONFIG_GOOGLE_FHD)

    # Include paths
    zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR})
    zephyr_include_directories(${ZEPHYR_BASE}/../modules/crypto/mbedtls/include)
    zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/micro-ecc)


    # Tell Zephyr this is a library
    zephyr_library()

    
      # Inject the VLI API define into this library’s compile flags
    target_compile_definitions(${ZEPHYR_CURRENT_LIBRARY}
        PRIVATE uECC_ENABLE_VLI_API=1
        PRIVATE MBEDTLS_CONFIG_FILE="google_fhd_mbedtls_config.h"
    )

    # Add your main source file
    zephyr_library_sources(
        google_fhd.cpp
        micro-ecc/uECC.c
        google_fhd_mbedtls_config.h
    )
endif()

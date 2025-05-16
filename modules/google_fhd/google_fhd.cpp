#include <zephyr/kernel.h>
#include <psa/crypto.h>

#include "google_fhd.h"

GoogleFhd::GoogleFhd()
{
    initialized = false;
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

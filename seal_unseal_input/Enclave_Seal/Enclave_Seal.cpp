#include "Enclave_Seal_t.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include <stdio.h>
#include <string.h>

char add_mac_text[16] = "Add mac text";

uint32_t get_sealed_data_size(const char *plaintext) {
    return sgx_calc_sealed_data_size((uint32_t) strlen(add_mac_text), (uint32_t) strlen(plaintext));
}

sgx_status_t ecall_seal_data(const char *plaintext, uint8_t *sealed_blob, uint32_t data_size) {
    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(add_mac_text), (uint32_t)strlen(plaintext));

    if (sealed_data_size == UINT32_MAX) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (sealed_data_size > data_size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // sgx_seal_data(add_mac_text_length, add_mac_text, data_to_encrypt_length, data_to_encrypt, sealed_data_size, sealed_buffer)
    sgx_status_t  ret = sgx_seal_data((uint32_t) strlen(add_mac_text), (const uint8_t *) add_mac_text,
                                    (uint32_t) strlen(plaintext), (uint8_t *) plaintext, sealed_data_size,
                                    (sgx_sealed_data_t *) sealed_blob);

    return ret;
}

#include "Enclave_Unseal_t.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include <stdio.h>

uint8_t de_mac_text[256];

sgx_status_t ecall_unseal_data(uint8_t *decrypted_data, const uint8_t *sealed_blob, size_t data_size) {
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);

    if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX) {
        return SGX_ERROR_UNEXPECTED;
    }
    if(mac_text_len > data_size || decrypt_data_len > data_size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // sgx_unseal_data(sealed_buffer, decrypted_mac_text, &mac_text_len, unsealed_buffer, &decrypted_data_len)
    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *) sealed_blob, de_mac_text, &mac_text_len,
                                        decrypted_data, &decrypt_data_len);

    return ret;
}

// #include "Enclave_Crypto.h"
#include "Enclave_Seal_t.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"
// #include <openssl/rand.h>

#include <stdio.h>
#include <string.h>

char add_mac_text[16] = "Add mac text";

uint32_t get_sealed_data_size(const char *ori_data) {
    return sgx_calc_sealed_data_size((uint32_t) strlen(add_mac_text), (uint32_t) strlen(ori_data));
}

sgx_status_t ecall_seal_aes_key(uint8_t *sealed_blob, uint32_t data_size) {

    // /* Generate random values as AES key */
    // unsigned char aes_key[17];
    // int rand_ret = RAND_bytes(aes_key, sizeof(aes_key) - 1);
    // if (!rand_ret) {
    //     return (sgx_status_t) rand_ret;
    // }

    /* Use AES key from Enclave_Crypto.h */
	sgx_aes_gcm_128bit_key_t aes_key = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
    char aes_key_str_arr[16][2];
    for (int i = 0; i < sizeof(aes_key); i++) {
        snprintf(aes_key_str_arr[i], sizeof(unsigned char) * 2, "%x", aes_key[i]);    /* Account for null termination */
        // ocall_print_string(aes_key_str_arr[i]);
    }

    char aes_key_str[17];
    aes_key_str[16] = '\0';
    for (int i = 0; i < sizeof(aes_key); i++) {
        aes_key_str[i] = aes_key_str_arr[i][0];
    }
    ocall_print_string("AES Key from inside enclave:");
    ocall_print_string(aes_key_str);

    uint32_t sealed_data_size = get_sealed_data_size(aes_key_str);
    // ocall_print_int(sealed_data_size);
    // ocall_print_int(data_size);

    if (sealed_data_size == UINT32_MAX) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (sealed_data_size > data_size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // sgx_seal_data(add_mac_text_length, add_mac_text, data_to_encrypt_length, data_to_encrypt, sealed_data_size, sealed_buffer)
    sgx_status_t ret = sgx_seal_data((uint32_t) strlen(add_mac_text), (const uint8_t *) add_mac_text,
                                    (uint32_t) strlen(aes_key_str), (uint8_t *) aes_key_str, sealed_data_size,
                                    (sgx_sealed_data_t *) sealed_blob);

    return ret;
}

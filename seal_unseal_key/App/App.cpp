#include <iostream>
#include <string>
#include <fstream>

#include <assert.h>
#include <string.h>

#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "App.h"
#include "Enclave_Seal_u.h"
#include "Enclave_Unseal_u.h"
#include "ErrorSupport.h"

#define ENCLAVE_NAME_SEAL "enclave_seal.signed.so"
#define ENCLAVE_NAME_UNSEAL "enclave_unseal.signed.so"
#define SEALED_DATA_FILE "sealed_data_blob.txt"

char input_file[256];

/* Prints string passed from inside enclave */
void ocall_print_string(const char *str) {
    std::cout << str << std::endl;
}

/* Prints char passed from inside enclave */
void ocall_print_byte(char c) {
    printf("%c\n", c);
}

/* Prints int passed from inside enclave */
void ocall_print_int(int num) {
    std::cout << num << std::endl;
}

static size_t get_file_size(const char *filename)
{
    std::ifstream ifs(filename, std::ios::in | std::ios::binary);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return -1;
    }
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    return size;
}

static bool read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;

    std::ifstream ifs(filename, std::ios::binary | std::ios::in);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }

    ifs.read(reinterpret_cast<char *> (buf), bsize);
    if (ifs.fail())
    {
        std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
        return false;
    }

    return true;
}

static bool write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;

    std::ofstream ofs(filename, std::ios::binary | std::ios::out);
    if (!ofs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }

    ofs.seekp(offset, std::ios::beg);
    ofs.write(reinterpret_cast<const char*>(buf), bsize);
    if (ofs.fail())
    {
        std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
        return false;
    }

    return true;
}

/* Initialize the enclave:
*   Call sgx_create_enclave to initialize an enclave instance
*/
static sgx_status_t initialize_enclave(const char* enclave_path, sgx_enclave_id_t *eid)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    return SGX_SUCCESS;
}

/*
 * Makes ECALL to create sealed data and store to temp buffer, then write to sealed file
 */
static bool seal_and_save_aes_key()
{
    sgx_enclave_id_t eid_seal = 0;
    // Load the enclave for sealing
    sgx_status_t ret = initialize_enclave(ENCLAVE_NAME_SEAL, &eid_seal);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return false;
    }

    // Simulate 16-byte AES key size
    // sgx_aes_gcm_128bit_key_t aes_key_sim = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
    char aes_key_sim[17] = "0000000000000000";
    uint32_t sealed_data_size = 0;
    ret = get_sealed_data_size(eid_seal, &sealed_data_size, aes_key_sim);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if(sealed_data_size == UINT32_MAX)
    {
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    uint8_t *temp_sealed_buf = (uint8_t *) malloc(sealed_data_size);
    if (temp_sealed_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    sgx_status_t retval;
    ret = ecall_seal_aes_key(eid_seal, &retval, temp_sealed_buf, sealed_data_size);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if(retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    // Save the sealed blob
    if (write_buf_to_file(SEALED_DATA_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
    {
        std::cout << "Failed to save the sealed data blob to \"" << SEALED_DATA_FILE << "\"" << std::endl;
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    std::cout << "Sealing data succeeded." << std::endl;
    std::cout << "Sealed as: " << temp_sealed_buf << std::endl;

    free(temp_sealed_buf);
    sgx_destroy_enclave(eid_seal);
    return true;

}

/*
 * Read sealed data from sealed file to temp buffer, then make ECALL to unseal data
 */
static bool read_and_unseal_aes_key()
{
    sgx_enclave_id_t eid_unseal = 0;
    uint8_t decrypted_data[17];

    // Load the enclave for unsealing
    sgx_status_t ret = initialize_enclave(ENCLAVE_NAME_UNSEAL, &eid_unseal);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return false;
    }
    
    // Read the sealed blob from the file
    size_t fsize = get_file_size(SEALED_DATA_FILE);
    if (fsize == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << SEALED_DATA_FILE << "\"" << std::endl;
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    uint8_t *temp_buf = (uint8_t *) malloc(fsize);
    if(temp_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    if (read_file_to_buf(SEALED_DATA_FILE, temp_buf, fsize) == false)
    {
        std::cout << "Failed to read the sealed data blob from \"" << SEALED_DATA_FILE << "\"" << std::endl;
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    // Unseal the sealed blob
    sgx_status_t retval;
    ret = ecall_unseal_data(eid_unseal, &retval, decrypted_data, temp_buf, fsize);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    else if(retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    decrypted_data[17] = '\0';    /* strlen > sizeof for some reason */
    std::cout << "Unseal succeeded." << std::endl;
    std::cout << "Unsealed data: " << decrypted_data << std::endl;

    free(temp_buf);
    sgx_destroy_enclave(eid_unseal);
    return true;
}


int main(int argc, char* argv[])
{
    (void)argc, (void)argv;

    /* Enclave_Seal: Generate and seal the AES key then save the data blob to a file */
    if (seal_and_save_aes_key() == false)
    {
        std::cout << "Failed to seal the secret and save it to a file." << std::endl;
        return -1;
    }

    // Enclave_Unseal: read the data blob from the file and unseal it.
    if (read_and_unseal_aes_key() == false)
    {
        std::cout << "Failed to unseal the data blob." << std::endl;
        return -1;
    }

    return 0;
}

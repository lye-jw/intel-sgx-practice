#include "../App.h"
#include "Enclave_u.h"

/* ecall_put_string:
 * Puts string into the enclave.
 */
void ecall_put_string(char *str) {
    int res = ecall_store_string(global_eid, str);

    if (res != SGX_SUCCESS) {
        printf("Put string operation failed!");
    }
}

/* ecall_retrieve_string:
 * Retrieves string from enclave and stores to buffer.
 */
void ecall_retrieve_string(char *buf) {
    int res = ecall_get_string(global_eid, buf);

    if (res != SGX_SUCCESS) {
        printf("Retrieve string operation failed!");
    }
}


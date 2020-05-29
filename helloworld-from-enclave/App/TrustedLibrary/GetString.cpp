#include "../App.h"
#include "Enclave_u.h"

/* ecall_retrieve:
 * Retrieves string from inside enclave.
 */
void ecall_retrieve(void) {
    int res = ecall_get_string(global_eid);

    if (res != SGX_SUCCESS) {
        printf("Retrieval operation failed!");
    }
}
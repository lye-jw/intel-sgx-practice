#include <string.h>
#include "../Enclave.h"
#include "Enclave_t.h"

/* ecall_retrieve:
 * Retrieves string from inside enclave.
 */
void ecall_get_string(void) {
    ocall_print_string("Hello World!"); // return "Hello World!"
}

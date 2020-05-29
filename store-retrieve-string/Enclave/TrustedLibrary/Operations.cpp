#include <string.h>

#include "../Enclave.h"
#include "Enclave_t.h"

/* ecall_store_string:
 * Stores provided string as the global string.
 */
void ecall_store_string(char *str) {
    strlcpy(stored_str, str, sizeof(stored_str));   /* Ensure str length <= stored_str length */
}


/* ecall_get_string:
 * Gets the global string and stores it in untrusted buffer.
 */
void ecall_get_string(char *buf) {
    memcpy(buf, stored_str, strlen(buf) + 1);
}

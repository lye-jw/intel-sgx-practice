#include "Enclave.h"
#include "Enclave_t.h"
#include <stdio.h>

/* Global string store */
char stored_str[256];

void ecall_print_string(void) {
    ocall_print_string(stored_str);
}

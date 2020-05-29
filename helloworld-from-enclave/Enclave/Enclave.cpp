#include "Enclave.h"
#include "Enclave_t.h"
#include <stdio.h>
#include <string.h>

void enclave_print(void) {
    ocall_print_string("Hello World!");
}

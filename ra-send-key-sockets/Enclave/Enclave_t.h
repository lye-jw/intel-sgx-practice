#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_tkey_exchange.h"
#include "config.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t get_report(sgx_report_t* report, sgx_target_info_t* target_info);
sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse, sgx_ra_context_t* ctx, sgx_status_t* pse_status);
sgx_status_t enclave_ra_init_def(int b_pse, sgx_ra_context_t* ctx, sgx_status_t* pse_status);
sgx_status_t enclave_ra_get_key_hash(sgx_status_t* get_keys_status, sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t* hash);
sgx_status_t enclave_ra_close(sgx_ra_context_t ctx);
sgx_status_t enclave_seal_key(sgx_ra_context_t ctx, sgx_ra_key_type_t key_type, uint8_t* sealed_blob, uint32_t data_size);
sgx_status_t enclave_unseal_key(uint8_t* decrypted_data, const uint8_t* sealed_blob, size_t data_size);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

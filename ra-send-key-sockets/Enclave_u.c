#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_get_report_t {
	sgx_status_t ms_retval;
	sgx_report_t* ms_report;
	sgx_target_info_t* ms_target_info;
} ms_get_report_t;

typedef struct ms_enclave_ra_init_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t ms_key;
	int ms_b_pse;
	sgx_ra_context_t* ms_ctx;
	sgx_status_t* ms_pse_status;
} ms_enclave_ra_init_t;

typedef struct ms_enclave_ra_init_def_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_ctx;
	sgx_status_t* ms_pse_status;
} ms_enclave_ra_init_def_t;

typedef struct ms_enclave_ra_get_key_hash_t {
	sgx_status_t ms_retval;
	sgx_status_t* ms_get_keys_status;
	sgx_ra_context_t ms_ctx;
	sgx_ra_key_type_t ms_type;
	sgx_sha256_hash_t* ms_hash;
} ms_enclave_ra_get_key_hash_t;

typedef struct ms_enclave_ra_close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_ctx;
} ms_enclave_ra_close_t;

typedef struct ms_enclave_seal_key_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_ctx;
	sgx_ra_key_type_t ms_key_type;
	uint8_t* ms_sealed_blob;
	uint32_t ms_data_size;
} ms_enclave_seal_key_t;

typedef struct ms_enclave_unseal_key_t {
	sgx_status_t ms_retval;
	uint8_t* ms_decrypted_data;
	const uint8_t* ms_sealed_blob;
	size_t ms_data_size;
} ms_enclave_unseal_key_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t get_report(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_report_t* report, sgx_target_info_t* target_info)
{
	sgx_status_t status;
	ms_get_report_t ms;
	ms.ms_report = report;
	ms.ms_target_info = target_info;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_ra_init(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t key, int b_pse, sgx_ra_context_t* ctx, sgx_status_t* pse_status)
{
	sgx_status_t status;
	ms_enclave_ra_init_t ms;
	ms.ms_key = key;
	ms.ms_b_pse = b_pse;
	ms.ms_ctx = ctx;
	ms.ms_pse_status = pse_status;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_ra_init_def(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* ctx, sgx_status_t* pse_status)
{
	sgx_status_t status;
	ms_enclave_ra_init_def_t ms;
	ms.ms_b_pse = b_pse;
	ms.ms_ctx = ctx;
	ms.ms_pse_status = pse_status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_ra_get_key_hash(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_status_t* get_keys_status, sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t* hash)
{
	sgx_status_t status;
	ms_enclave_ra_get_key_hash_t ms;
	ms.ms_get_keys_status = get_keys_status;
	ms.ms_ctx = ctx;
	ms.ms_type = type;
	ms.ms_hash = hash;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t ctx)
{
	sgx_status_t status;
	ms_enclave_ra_close_t ms;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_seal_key(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t ctx, sgx_ra_key_type_t key_type, uint8_t* sealed_blob, uint32_t data_size)
{
	sgx_status_t status;
	ms_enclave_seal_key_t ms;
	ms.ms_ctx = ctx;
	ms.ms_key_type = key_type;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_unseal_key(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* decrypted_data, const uint8_t* sealed_blob, size_t data_size)
{
	sgx_status_t status;
	ms_enclave_unseal_key_t ms;
	ms.ms_decrypted_data = decrypted_data;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = p_msg2;
	ms.ms_p_qe_target = p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}


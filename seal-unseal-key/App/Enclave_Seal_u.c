#include "Enclave_Seal_u.h"
#include <errno.h>

typedef struct ms_get_sealed_data_size_t {
	uint32_t ms_retval;
	const char* ms_ori_data;
	size_t ms_ori_data_len;
} ms_get_sealed_data_size_t;

typedef struct ms_ecall_seal_aes_key_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_blob;
	uint32_t ms_data_size;
} ms_ecall_seal_aes_key_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_print_byte_t {
	char ms_c;
} ms_ocall_print_byte_t;

typedef struct ms_ocall_print_int_t {
	int ms_num;
} ms_ocall_print_int_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_Seal_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_ocall_print_byte(void* pms)
{
	ms_ocall_print_byte_t* ms = SGX_CAST(ms_ocall_print_byte_t*, pms);
	ocall_print_byte(ms->ms_c);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_ocall_print_int(void* pms)
{
	ms_ocall_print_int_t* ms = SGX_CAST(ms_ocall_print_int_t*, pms);
	ocall_print_int(ms->ms_num);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[8];
} ocall_table_Enclave_Seal = {
	8,
	{
		(void*)Enclave_Seal_ocall_print_string,
		(void*)Enclave_Seal_ocall_print_byte,
		(void*)Enclave_Seal_ocall_print_int,
		(void*)Enclave_Seal_sgx_oc_cpuidex,
		(void*)Enclave_Seal_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_Seal_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_Seal_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_Seal_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, const char* ori_data)
{
	sgx_status_t status;
	ms_get_sealed_data_size_t ms;
	ms.ms_ori_data = ori_data;
	ms.ms_ori_data_len = ori_data ? strlen(ori_data) + 1 : 0;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_seal_aes_key(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_blob, uint32_t data_size)
{
	sgx_status_t status;
	ms_ecall_seal_aes_key_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}


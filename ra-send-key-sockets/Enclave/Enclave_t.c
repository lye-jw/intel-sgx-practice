#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_get_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_report_t* ms = SGX_CAST(ms_get_report_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_report = ms->ms_report;
	size_t _len_report = sizeof(sgx_report_t);
	sgx_report_t* _in_report = NULL;
	sgx_target_info_t* _tmp_target_info = ms->ms_target_info;
	size_t _len_target_info = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_target_info = NULL;

	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);
	CHECK_UNIQUE_POINTER(_tmp_target_info, _len_target_info);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_report != NULL && _len_report != 0) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}
	if (_tmp_target_info != NULL && _len_target_info != 0) {
		_in_target_info = (sgx_target_info_t*)malloc(_len_target_info);
		if (_in_target_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_target_info, _len_target_info, _tmp_target_info, _len_target_info)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = get_report(_in_report, _in_target_info);
	if (_in_report) {
		if (memcpy_s(_tmp_report, _len_report, _in_report, _len_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_report) free(_in_report);
	if (_in_target_info) free(_in_target_info);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_ra_init_t* ms = SGX_CAST(ms_enclave_ra_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_ctx = ms->ms_ctx;
	size_t _len_ctx = sizeof(sgx_ra_context_t);
	sgx_ra_context_t* _in_ctx = NULL;
	sgx_status_t* _tmp_pse_status = ms->ms_pse_status;
	size_t _len_pse_status = sizeof(sgx_status_t);
	sgx_status_t* _in_pse_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ctx, _len_ctx);
	CHECK_UNIQUE_POINTER(_tmp_pse_status, _len_pse_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ctx != NULL && _len_ctx != 0) {
		if ((_in_ctx = (sgx_ra_context_t*)malloc(_len_ctx)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ctx, 0, _len_ctx);
	}
	if (_tmp_pse_status != NULL && _len_pse_status != 0) {
		if ((_in_pse_status = (sgx_status_t*)malloc(_len_pse_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pse_status, 0, _len_pse_status);
	}

	ms->ms_retval = enclave_ra_init(ms->ms_key, ms->ms_b_pse, _in_ctx, _in_pse_status);
	if (_in_ctx) {
		if (memcpy_s(_tmp_ctx, _len_ctx, _in_ctx, _len_ctx)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_pse_status) {
		if (memcpy_s(_tmp_pse_status, _len_pse_status, _in_pse_status, _len_pse_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ctx) free(_in_ctx);
	if (_in_pse_status) free(_in_pse_status);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_init_def(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_init_def_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_ra_init_def_t* ms = SGX_CAST(ms_enclave_ra_init_def_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_ctx = ms->ms_ctx;
	size_t _len_ctx = sizeof(sgx_ra_context_t);
	sgx_ra_context_t* _in_ctx = NULL;
	sgx_status_t* _tmp_pse_status = ms->ms_pse_status;
	size_t _len_pse_status = sizeof(sgx_status_t);
	sgx_status_t* _in_pse_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ctx, _len_ctx);
	CHECK_UNIQUE_POINTER(_tmp_pse_status, _len_pse_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ctx != NULL && _len_ctx != 0) {
		if ((_in_ctx = (sgx_ra_context_t*)malloc(_len_ctx)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ctx, 0, _len_ctx);
	}
	if (_tmp_pse_status != NULL && _len_pse_status != 0) {
		if ((_in_pse_status = (sgx_status_t*)malloc(_len_pse_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pse_status, 0, _len_pse_status);
	}

	ms->ms_retval = enclave_ra_init_def(ms->ms_b_pse, _in_ctx, _in_pse_status);
	if (_in_ctx) {
		if (memcpy_s(_tmp_ctx, _len_ctx, _in_ctx, _len_ctx)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_pse_status) {
		if (memcpy_s(_tmp_pse_status, _len_pse_status, _in_pse_status, _len_pse_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ctx) free(_in_ctx);
	if (_in_pse_status) free(_in_pse_status);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_get_key_hash(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_get_key_hash_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_ra_get_key_hash_t* ms = SGX_CAST(ms_enclave_ra_get_key_hash_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t* _tmp_get_keys_status = ms->ms_get_keys_status;
	size_t _len_get_keys_status = sizeof(sgx_status_t);
	sgx_status_t* _in_get_keys_status = NULL;
	sgx_sha256_hash_t* _tmp_hash = ms->ms_hash;
	size_t _len_hash = sizeof(sgx_sha256_hash_t);
	sgx_sha256_hash_t* _in_hash = NULL;

	CHECK_UNIQUE_POINTER(_tmp_get_keys_status, _len_get_keys_status);
	CHECK_UNIQUE_POINTER(_tmp_hash, _len_hash);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_get_keys_status != NULL && _len_get_keys_status != 0) {
		if ((_in_get_keys_status = (sgx_status_t*)malloc(_len_get_keys_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_get_keys_status, 0, _len_get_keys_status);
	}
	if (_tmp_hash != NULL && _len_hash != 0) {
		if ((_in_hash = (sgx_sha256_hash_t*)malloc(_len_hash)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_hash, 0, _len_hash);
	}

	ms->ms_retval = enclave_ra_get_key_hash(_in_get_keys_status, ms->ms_ctx, ms->ms_type, _in_hash);
	if (_in_get_keys_status) {
		if (memcpy_s(_tmp_get_keys_status, _len_get_keys_status, _in_get_keys_status, _len_get_keys_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_hash) {
		if (memcpy_s(_tmp_hash, _len_hash, _in_hash, _len_hash)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_get_keys_status) free(_in_get_keys_status);
	if (_in_hash) free(_in_hash);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_ra_close_t* ms = SGX_CAST(ms_enclave_ra_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enclave_ra_close(ms->ms_ctx);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_seal_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_seal_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_seal_key_t* ms = SGX_CAST(ms_enclave_seal_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_blob = ms->ms_sealed_blob;
	uint32_t _tmp_data_size = ms->ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_blob, 0, _len_sealed_blob);
	}

	ms->ms_retval = enclave_seal_key(ms->ms_ctx, ms->ms_key_type, _in_sealed_blob, _tmp_data_size);
	if (_in_sealed_blob) {
		if (memcpy_s(_tmp_sealed_blob, _len_sealed_blob, _in_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_blob) free(_in_sealed_blob);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_unseal_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_unseal_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_unseal_key_t* ms = SGX_CAST(ms_enclave_unseal_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_decrypted_data = ms->ms_decrypted_data;
	size_t _tmp_data_size = ms->ms_data_size;
	size_t _len_decrypted_data = _tmp_data_size;
	uint8_t* _in_decrypted_data = NULL;
	const uint8_t* _tmp_sealed_blob = ms->ms_sealed_blob;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;

	CHECK_UNIQUE_POINTER(_tmp_decrypted_data, _len_decrypted_data);
	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_decrypted_data != NULL && _len_decrypted_data != 0) {
		if ( _len_decrypted_data % sizeof(*_tmp_decrypted_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_decrypted_data = (uint8_t*)malloc(_len_decrypted_data);
		if (_in_decrypted_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_decrypted_data, _len_decrypted_data, _tmp_decrypted_data, _len_decrypted_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob);
		if (_in_sealed_blob == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_blob, _len_sealed_blob, _tmp_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enclave_unseal_key(_in_decrypted_data, (const uint8_t*)_in_sealed_blob, _tmp_data_size);
	if (_in_decrypted_data) {
		if (memcpy_s(_tmp_decrypted_data, _len_decrypted_data, _in_decrypted_data, _len_decrypted_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_decrypted_data) free(_in_decrypted_data);
	if (_in_sealed_blob) free(_in_sealed_blob);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_g_a = NULL;

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_a != NULL && _len_g_a != 0) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}

	ms->ms_retval = sgx_ra_get_ga(ms->ms_context, _in_g_a);
	if (_in_g_a) {
		if (memcpy_s(_tmp_g_a, _len_g_a, _in_g_a, _len_g_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_g_a) free(_in_g_a);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgx_ra_msg2_t* _tmp_p_msg2 = ms->ms_p_msg2;
	size_t _len_p_msg2 = sizeof(sgx_ra_msg2_t);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	const sgx_target_info_t* _tmp_p_qe_target = ms->ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(sgx_report_t);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = ms->ms_p_nonce;
	size_t _len_p_nonce = sizeof(sgx_quote_nonce_t);
	sgx_quote_nonce_t* _in_p_nonce = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_msg2 != NULL && _len_p_msg2 != 0) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_msg2, _len_p_msg2, _tmp_p_msg2, _len_p_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_qe_target != NULL && _len_p_qe_target != 0) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_qe_target, _len_p_qe_target, _tmp_p_qe_target, _len_p_qe_target)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL && _len_p_nonce != 0) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}

	ms->ms_retval = sgx_ra_proc_msg2_trusted(ms->ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
	if (_in_p_report) {
		if (memcpy_s(_tmp_p_report, _len_p_report, _in_p_report, _len_p_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_nonce) {
		if (memcpy_s(_tmp_p_nonce, _len_p_nonce, _in_p_nonce, _len_p_nonce)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_msg2) free(_in_p_msg2);
	if (_in_p_qe_target) free(_in_p_qe_target);
	if (_in_p_report) free(_in_p_report);
	if (_in_p_nonce) free(_in_p_nonce);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = ms->ms_qe_report;
	size_t _len_qe_report = sizeof(sgx_report_t);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = ms->ms_p_msg3;

	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_qe_report != NULL && _len_qe_report != 0) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_qe_report, _len_qe_report, _tmp_qe_report, _len_qe_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = sgx_ra_get_msg3_trusted(ms->ms_context, ms->ms_quote_size, _in_qe_report, _tmp_p_msg3, ms->ms_msg3_size);

err:
	if (_in_qe_report) free(_in_qe_report);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[10];
} g_ecall_table = {
	10,
	{
		{(void*)(uintptr_t)sgx_get_report, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_init, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_init_def, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_get_key_hash, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_close, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_seal_key, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_unseal_key, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};



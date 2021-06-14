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


typedef struct ms_ecall_generate_keys_t {
	int ms_retval;
	const unsigned char* ms_data;
} ms_ecall_generate_keys_t;

typedef struct ms_ocall_enc_data_t {
	unsigned char* ms_penc_data;
	size_t* ms_size;
} ms_ocall_enc_data_t;

typedef struct ms_ocall_dec_data_t {
	unsigned char* ms_pdec_data;
	size_t* ms_size;
} ms_ocall_dec_data_t;

static sgx_status_t SGX_CDECL sgx_ecall_generate_keys(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_keys_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_keys_t* ms = SGX_CAST(ms_ecall_generate_keys_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_data = ms->ms_data;
	size_t _len_data = sizeof(unsigned char);
	unsigned char* _in_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (unsigned char*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_generate_keys((const unsigned char*)_in_data);

err:
	if (_in_data) free(_in_data);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_ecall_generate_keys, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][1];
} g_dyn_entry_table = {
	2,
	{
		{0, },
		{0, },
	}
};


sgx_status_t SGX_CDECL ocall_enc_data(unsigned char* penc_data, size_t* size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_penc_data = sizeof(unsigned char);
	size_t _len_size = sizeof(size_t);

	ms_ocall_enc_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_enc_data_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(penc_data, _len_penc_data);
	CHECK_ENCLAVE_POINTER(size, _len_size);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (penc_data != NULL) ? _len_penc_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (size != NULL) ? _len_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_enc_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_enc_data_t));
	ocalloc_size -= sizeof(ms_ocall_enc_data_t);

	if (penc_data != NULL) {
		ms->ms_penc_data = (unsigned char*)__tmp;
		if (_len_penc_data % sizeof(*penc_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, penc_data, _len_penc_data)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_penc_data);
		ocalloc_size -= _len_penc_data;
	} else {
		ms->ms_penc_data = NULL;
	}
	
	if (size != NULL) {
		ms->ms_size = (size_t*)__tmp;
		if (_len_size % sizeof(*size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, size, _len_size)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_size);
		ocalloc_size -= _len_size;
	} else {
		ms->ms_size = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_dec_data(unsigned char* pdec_data, size_t* size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pdec_data = sizeof(unsigned char);
	size_t _len_size = sizeof(size_t);

	ms_ocall_dec_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_dec_data_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pdec_data, _len_pdec_data);
	CHECK_ENCLAVE_POINTER(size, _len_size);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pdec_data != NULL) ? _len_pdec_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (size != NULL) ? _len_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_dec_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_dec_data_t));
	ocalloc_size -= sizeof(ms_ocall_dec_data_t);

	if (pdec_data != NULL) {
		ms->ms_pdec_data = (unsigned char*)__tmp;
		if (_len_pdec_data % sizeof(*pdec_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pdec_data, _len_pdec_data)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pdec_data);
		ocalloc_size -= _len_pdec_data;
	} else {
		ms->ms_pdec_data = NULL;
	}
	
	if (size != NULL) {
		ms->ms_size = (size_t*)__tmp;
		if (_len_size % sizeof(*size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, size, _len_size)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_size);
		ocalloc_size -= _len_size;
	} else {
		ms->ms_size = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}


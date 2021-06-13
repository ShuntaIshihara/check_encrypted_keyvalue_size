#include "Enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Enclave_ocall_enc_data(void* pms)
{
	ms_ocall_enc_data_t* ms = SGX_CAST(ms_ocall_enc_data_t*, pms);
	ocall_enc_data(ms->ms_penc_data, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_dec_data(void* pms)
{
	ms_ocall_dec_data_t* ms = SGX_CAST(ms_ocall_dec_data_t*, pms);
	ocall_dec_data(ms->ms_pdec_data, ms->ms_size);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_Enclave = {
	2,
	{
		(void*)Enclave_ocall_enc_data,
		(void*)Enclave_ocall_dec_data,
	}
};
sgx_status_t ecall_generate_keys(sgx_enclave_id_t eid, int* retval, const unsigned char* data)
{
	sgx_status_t status;
	ms_ecall_generate_keys_t ms;
	ms.ms_data = data;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}


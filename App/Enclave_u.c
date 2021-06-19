#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_generate_keys_t {
	int ms_retval;
	const unsigned char* ms_data;
	size_t ms_data_len;
} ms_ecall_generate_keys_t;

typedef struct ms_ocall_vname_t {
	const char* ms_v;
} ms_ocall_vname_t;

typedef struct ms_ocall_print_t {
	unsigned char* ms_data;
	size_t* ms_size;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL Enclave_ocall_vname(void* pms)
{
	ms_ocall_vname_t* ms = SGX_CAST(ms_ocall_vname_t*, pms);
	ocall_vname(ms->ms_v);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_data, ms->ms_size);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_Enclave = {
	2,
	{
		(void*)Enclave_ocall_vname,
		(void*)Enclave_ocall_print,
	}
};
sgx_status_t ecall_generate_keys(sgx_enclave_id_t eid, int* retval, const unsigned char* data)
{
	sgx_status_t status;
	ms_ecall_generate_keys_t ms;
	ms.ms_data = data;
	ms.ms_data_len = data ? strlen(data) + 1 : 0;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}


#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_generate_keys(const unsigned char* data);

sgx_status_t SGX_CDECL ocall_enc_data(unsigned char* penc_data, size_t* size);
sgx_status_t SGX_CDECL ocall_dec_data(unsigned char* pdec_data, size_t* size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

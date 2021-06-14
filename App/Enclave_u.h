#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_ENC_DATA_DEFINED__
#define OCALL_ENC_DATA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_enc_data, (unsigned char* penc_data, size_t* size));
#endif
#ifndef OCALL_DEC_DATA_DEFINED__
#define OCALL_DEC_DATA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_dec_data, (unsigned char* pdec_data, size_t* size));
#endif

sgx_status_t ecall_generate_keys(sgx_enclave_id_t eid, int* retval, const unsigned char* data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

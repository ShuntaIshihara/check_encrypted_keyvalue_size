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

#ifndef OCALL_VNAME_DEFINED__
#define OCALL_VNAME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_vname, (const char* v));
#endif
#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (unsigned char* data, size_t* size));
#endif

sgx_status_t ecall_generate_keys(sgx_enclave_id_t eid, int* retval, const unsigned char* data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

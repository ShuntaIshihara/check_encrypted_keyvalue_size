#include "Enclave_t.h"
#include <sgx_trts.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_tcrypto.h>

void *priv_key = NULL;
void *pub_key = NULL;

int ecall_generate_keys(const unsigned char *data)
{
    size_t s = sizeof(const unsigned char)*strlen((const char *)data);
    ocall_vname("data");
    ocall_print((unsigned char *)data, &s);

    //公開鍵と秘密鍵を生成
    //1. メモリ確保
    int n_byte_size = 256;
    int exp_byte_size = 256;
    unsigned char p_n[256];
    unsigned char p_d[256];
    unsigned char p_p[256];
    unsigned char p_q[256];
    unsigned char p_dmp1[256];
    unsigned char p_dmq1[256];
    unsigned char p_iqmp[256];
    long e = 65537;
    //2. 鍵の成分を生成
    sgx_status_t status = sgx_create_rsa_key_pair(n_byte_size, sizeof(e),
    p_n, p_d, (unsigned char *)&e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp);
    s = sizeof(unsigned char)*strlen((const char *)p_n);
    //3. 公開鍵と秘密鍵の生成
    status = sgx_create_rsa_priv2_key(n_byte_size, sizeof(e), (const unsigned char *)&e,
    (const unsigned char *)p_p, (const unsigned char *)p_q, (const unsigned char *)p_dmp1,
    (const unsigned char *)p_dmq1, (const unsigned char *)p_iqmp, &priv_key);
    s = strlen((const char *)priv_key);
    ocall_vname("priv_key");
    ocall_print((unsigned char *)priv_key, &s);

    status = sgx_create_rsa_pub1_key(n_byte_size, sizeof(e),
    (const unsigned char *)p_n, (const unsigned char *)&e, &pub_key);
    s = strlen((const char *)pub_key);
    ocall_vname("pub_key");
    ocall_print((unsigned char *)pub_key, &s);

    //暗号化
    size_t penc_len = 0;
    sgx_rsa_pub_encrypt_sha256(pub_key, NULL, &penc_len, (const unsigned char *)data,
    strlen((const char *)data)+1);
    unsigned char penc_data[penc_len];
    sgx_rsa_pub_encrypt_sha256(pub_key, penc_data, &penc_len, (const unsigned char *)data,
    strlen((const char *)data)+1);
    ocall_vname("penc_data");
    ocall_print(penc_data, &penc_len);

    //複合化
    size_t pdec_len = 0;
    sgx_rsa_priv_decrypt_sha256(priv_key, NULL, &pdec_len, (const unsigned char *)penc_data,
    strlen((const char *)penc_data));
    unsigned char pdec_data[pdec_len];
    sgx_rsa_priv_decrypt_sha256(priv_key, pdec_data, &pdec_len, (const unsigned char *)penc_data,
    strlen((const char *)penc_data));
    ocall_vname("pdec_data");
    ocall_print(pdec_data, &pdec_len);

    //公開鍵だけ返す
	return 1;
}

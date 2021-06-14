#include "Enclave_t.h"
#include <sgx_trts.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_tcrypto.h>

void *priv_key = malloc(256);
void *pub_key = malloc(256);

int ecall_generate_keys(const unsigned char *data)
{

    //公開鍵と秘密鍵を生成
    //1. メモリ確保
    int n_byte_size = 256;
    int e_byte_size = 3;
    int exp_byte_size = 256;
    unsigned char *p_n = (unsigned char *)malloc(n_byte_size);
    unsigned char *p_d = (unsigned char *)malloc(n_byte_size);
    unsigned char *p_e = (unsigned char *)malloc(e_byte_size);
    unsigned char *p_p = (unsigned char *)malloc(n_byte_size/2);
    unsigned char *p_q = (unsigned char *)malloc(n_byte_size/2);
    unsigned char *p_dmp1 = (unsigned char *)malloc(n_byte_size/2);
    unsigned char *p_dmq1 = (unsigned char *)malloc(n_byte_size/2);
    unsigned char *p_iqmp = (unsigned char *)malloc(n_byte_size/2);
    //2. 鍵の成分を生成
    sgx_status_t s = sgx_create_rsa_key_pair(n_byte_size, e_byte_size,
    p_n, p_d, p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp);
    //3. 公開鍵と秘密鍵の生成
    s = sgx_create_rsa_priv1_key(256, 3, 256, p_n, p_e, p_d, &priv_key);
//    s = sgx_create_rsa_priv2_key(n_byte_size, exp_byte_size, 
//    p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp, &priv_key); /*CRT用*/
    s = sgx_create_rsa_pub1_key(n_byte_size, exp_byte_size, 
    p_n, p_e, &pub_key);

    //暗号化
    unsigned char *penc_data = (unsigned char *)malloc(256);
    size_t *penc_len = (size_t *)malloc(sizeof(size_t));
    sgx_rsa_pub_encrypt_sha256(pub_key, penc_data, penc_len, (const unsigned char *)data, sizeof(data));

    ocall_enc_data(penc_data, penc_len);

    //複合化
    unsigned char *pdec_data = (unsigned char *)malloc(256);
    size_t *pdec_len = (size_t *)malloc(sizeof(size_t));
    sgx_rsa_priv_decrypt_sha256(priv_key, pdec_data, pdec_len, penc_data, *penc_len);

    ocall_dec_data(pdec_data, pdec_len);

    free(priv_key); free(pub_key);
    free(p_n); free(p_e), free(p_d), free(p_p); free(p_q); free(p_dmp1); free(p_dmq1); free(p_iqmp);
    //公開鍵だけ返す
	return 1;
}

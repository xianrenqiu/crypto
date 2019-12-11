#ifndef __CRYPTO_API_H__
#define __CRYPTO_API_H__

#include <stdint.h>
#include <stdio.h>

#define CRYPTO_RSA_MAX_BITS                2048

typedef enum crypto_ret_code_
{
    CRYPTO_RET_SUCCESS = 0,
    CRYPTO_RET_FAILED,
} crypto_ret_code_e;

typedef enum crypto_algo_
{
    PKE_ECP256R1,
    PKE_CURVE_25519,
    MD_ALGO_SHA1,
    MD_ALGO_SHA256,
    MD_ALGO_SHA384,
    MD_ALGO_SHA512,
    MD_ALGO_SM3,
    CIPHER_AES,
    CIPHER_SM4,
} crypto_algo_e;

typedef enum crypto_cipher_mode_
{
    CIPHER_MODE_ECB,
    CIPHER_MODE_CBC,
    CIPHER_MODE_CTR,
    CIPHER_MODE_GCM
} crypto_cipher_mode_e;

/** RSA 密钥结构 */
typedef struct rsa_key_
{
    int crt;
    int bits;                                     // 位数，1024/2048
    
    // key pair
    uint8_t n[CRYPTO_RSA_MAX_BITS];               // 模数
    uint8_t e[CRYPTO_RSA_MAX_BITS];               // 公开指数
    uint8_t d[CRYPTO_RSA_MAX_BITS];               // 私密指数

    // crt
    uint8_t p[CRYPTO_RSA_MAX_BITS/2];             // p        
    uint8_t q[CRYPTO_RSA_MAX_BITS/2];             // q
    uint8_t dp[CRYPTO_RSA_MAX_BITS/2];            // d mod (p-1)
    uint8_t dq[CRYPTO_RSA_MAX_BITS/2];            // d mod (q-1)
    uint8_t qinv[CRYPTO_RSA_MAX_BITS/2];          // (inverse of q) mod p
} crypto_rsa_key_t;

int crypto_random(uint8_t *buf, uint32_t size);
int crypto_md(uint8_t algo, uint8_t *src, uint32_t len, uint8_t *digest);
int crypto_hmac(uint8_t algo, uint8_t *src, uint32_t len, uint8_t *mac);
int crypto_cipher(uint8_t algo, uint8_t mode, uint8_t enc, uint8_t *key, uint32_t key_len, 
            uint8_t *iv, uint32_t iv_len, uint8_t *aad, uint32_t aad_len, uint8_t *src, uint32_t src_len, uint8_t *dst, uint8_t tag[16]);
int crypto_prf_algo(uint8_t hash_algo, uint8_t *sec, uint32_t seclen, uint8_t *seed, uint32_t seedlen, uint8_t *out, uint32_t outlen);

int crypto_rsa_gen_keypair(crypto_rsa_key_t *rsa_key);
int crypto_rsa_pub_enc(uint8_t bits, uint8_t *e, uint8_t *n, uint8_t *in, uint8_t *out);
int crypto_rsa_pub_dec(uint8_t bits, uint8_t *e, uint8_t *n, uint8_t *in, uint8_t *out);
int crypto_rsa_priv_enc(crypto_rsa_key_t *key, uint8_t *in, uint8_t *out);
int crypto_rsa_priv_dec(crypto_rsa_key_t *key, uint8_t *in, uint8_t *out);

// ecp256r1/curve25519
int crypto_ecc_gen_prikey(uint8_t algo, uint8_t prikey[32]);
int crypto_ecc_kg(uint8_t algo, uint8_t k[32], uint8_t r[64]);
int crypto_ecc_kp(uint8_t algo, uint8_t k[32], uint8_t p[64], uint8_t r[64]);
int crypto_ecdsa_sign(uint8_t algo, uint8_t prikey[32], uint8_t digest[32], uint8_t sign[32]);
int crypto_ecdsa_verify(uint8_t algo, uint8_t pubkey[32], uint8_t digest[32], uint8_t sign[32]);

int crypto_sm2_gen_prikey(uint8_t prikey[32]);
int crypto_sm2_kg(uint8_t k[32], uint8_t r[64]);
int crypto_sm2_kp(uint8_t k[32], uint8_t p[64], uint8_t r[64]);
int crypto_sm2_sign(uint8_t prikey[32], uint8_t digest[32], uint8_t sign[64]);
int crypto_sm2_verify(uint8_t pubkey[64], uint8_t digest[32], uint8_t sign[64]);
int crypto_sm2_encrypt(uint8_t pubkey[64], uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t *outlen);
int crypto_sm2_decrypt(uint8_t prikey[32], uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t *outlen);

// for debug
#define crypto_assert(cond)                                             \
    do                                                                  \
    {                                                                   \
        if (!(cond))                                                    \
        {                                                               \
            printf("\n  assert: !failed, %s:%d\n", __FILE__, __LINE__); \
            return CRYPTO_RET_FAILED;                                   \
        }                                                               \
    } while (0)

void dump_buf(char *info, uint8_t *buf, uint32_t len);

#endif
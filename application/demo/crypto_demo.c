#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "crypto_api.h"
#include "vector.h"
		
int md_demo(void)
{
	uint8_t out[64];
	assert(crypto_md(MD_ALGO_SHA1, md_msg, sizeof(md_msg), out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, md_sha1_digest_ok, sizeof(md_sha1_digest_ok)) == 0);

	assert(crypto_md(MD_ALGO_SHA256, md_msg, sizeof(md_msg), out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, md_sha256_digest_ok, sizeof(md_sha256_digest_ok)) == 0);
	
	assert(crypto_md(MD_ALGO_SHA384, md_msg, sizeof(md_msg), out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, md_sha384_digest_ok, sizeof(md_sha384_digest_ok)) == 0);

	assert(crypto_md(MD_ALGO_SHA512, md_msg, sizeof(md_msg), out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, md_sha512_digest_ok, sizeof(md_sha512_digest_ok)) == 0);

	assert(crypto_md(MD_ALGO_SM3, md_msg, sizeof(md_msg), out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, md_sm3_digest_ok, sizeof(md_sm3_digest_ok)) == 0);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int cipher_demo(void)
{
	uint8_t out[16];
	uint8_t tag[16];
	assert(crypto_cipher(CIPHER_AES, CIPHER_MODE_GCM, 1, gcm_key, sizeof(gcm_key), 
            gcm_iv, sizeof(gcm_iv), gcm_aad, sizeof(gcm_aad), gcm_in, sizeof(gcm_in), out, tag) == CRYPTO_RET_SUCCESS);
	
	assert(memcmp(out, gcm_rst, sizeof(gcm_rst)) == 0);
	assert(memcmp(tag, gcm_tag, sizeof(gcm_tag)) == 0);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int hmac_demo(void)
{
	uint8_t out[64];
	assert(crypto_hmac(MD_ALGO_SHA1, hmac_key, sizeof(hmac_key), hmac_msg, sizeof(hmac_msg), out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, hmac_sha1_result, sizeof(hmac_sha1_result)) == 0);

	assert(crypto_hmac(MD_ALGO_SHA256, hmac_key, sizeof(hmac_key), hmac_msg, sizeof(hmac_msg), out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, hmac_sha256_result, sizeof(hmac_sha256_result)) == 0);

	assert(crypto_hmac(MD_ALGO_SHA384, hmac_key, sizeof(hmac_key), hmac_msg, sizeof(hmac_msg), out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, hmac_sha384_result, sizeof(hmac_sha384_result)) == 0);

	assert(crypto_hmac(MD_ALGO_SHA512, hmac_key, sizeof(hmac_key), hmac_msg, sizeof(hmac_msg), out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, hmac_sha512_result, sizeof(hmac_sha512_result)) == 0);

	assert(crypto_hmac(MD_ALGO_SM3, hmac_key, sizeof(hmac_key), hmac_msg, sizeof(hmac_msg), out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, hmac_sm3_result, sizeof(hmac_sm3_result)) == 0);
	
	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int prf_demo(void)
{
	uint8_t out[64];
	assert(crypto_prf(MD_ALGO_SHA1, prf_secret, sizeof(prf_secret), prf_seed, sizeof(prf_seed), out, sizeof(out)) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, prf_keyblock_sha1, sizeof(prf_keyblock_sha1)) == 0);

	assert(crypto_prf(MD_ALGO_SHA256, prf_secret, sizeof(prf_secret), prf_seed, sizeof(prf_seed), out, sizeof(out)) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, prf_keyblock_sha256, sizeof(prf_keyblock_sha256)) == 0);

	assert(crypto_prf(MD_ALGO_SHA384, prf_secret, sizeof(prf_secret), prf_seed, sizeof(prf_seed), out, sizeof(out)) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, prf_keyblock_sha384, sizeof(prf_keyblock_sha384)) == 0);

	assert(crypto_prf(MD_ALGO_SM3, prf_secret, sizeof(prf_secret), prf_seed, sizeof(prf_seed), out, sizeof(out)) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, prf_keyblock_sm3, sizeof(prf_keyblock_sm3)) == 0);
	
	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int rsa_sign_demo(void)
{
	uint8_t out[256];
	crypto_rsa_key_t rsa_key;
	rsa_key.bits = 2048;
	memcpy(rsa_key.n, rsa2048_n, sizeof(rsa2048_n));
	memcpy(rsa_key.e, rsa2048_e, sizeof(rsa2048_e));
	memcpy(rsa_key.d, rsa2048_d, sizeof(rsa2048_d));

	assert(crypto_rsa_priv_enc(&rsa_key, rsa2048_msg, out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, rsa2048_signature, sizeof(rsa2048_signature)) == 0);
	
	assert(crypto_rsa_pub_dec(&rsa_key, out, out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, rsa2048_msg, sizeof(rsa2048_msg)) == 0);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int rsa_enc_demo(void)
{
	uint8_t out[256];
	crypto_rsa_key_t rsa_key;
	rsa_key.bits = 2048;
	memcpy(rsa_key.n, rsa2048_n, sizeof(rsa2048_n));
	memcpy(rsa_key.e, rsa2048_e, sizeof(rsa2048_e));
	memcpy(rsa_key.d, rsa2048_d, sizeof(rsa2048_d));

	assert(crypto_rsa_pub_enc(&rsa_key, rsa2048_msg, out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, rsa2048_pubkey_enc_result, sizeof(rsa2048_pubkey_enc_result)) == 0);
	
	assert(crypto_rsa_priv_dec(&rsa_key, out, out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, rsa2048_msg, sizeof(rsa2048_msg)) == 0);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int sm2_kg_demo(void)
{
	uint8_t out[64];
	assert(crypto_sm2_kg(sm2_prikey, out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, sm2_pubkey, sizeof(sm2_pubkey)) == 0);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int sm2_kp_demo(void)
{
	uint8_t out[64];
	assert(crypto_sm2_kp(sm2_prikey, sm2_pubkey, out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, sm2_kp_result, sizeof(sm2_kp_result)) == 0);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int sm2_sign_demo(void)
{
	uint8_t out[64];
	assert(crypto_sm2_sign(sm2_prikey, sm2_msg, out) == CRYPTO_RET_SUCCESS);
	assert(crypto_sm2_verify(sm2_pubkey, sm2_msg, out) == CRYPTO_RET_SUCCESS);
	
	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int sm2_enc_demo(void)
{
	uint8_t out[256];
	uint32_t len = 256;
	assert(crypto_sm2_encrypt(sm2_pubkey, sm2_msg, sizeof(sm2_msg), out, &len) == CRYPTO_RET_SUCCESS);
	assert(crypto_sm2_decrypt(sm2_prikey, out, len, out, &len) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, sm2_msg, len) == 0);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int x25519_kg_demo(void)
{
	uint8_t out[64];
	assert(crypto_x25519_kg(x25519_prikey, out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, x25519_pubkey, sizeof(x25519_pubkey)) == 0);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int x25519_kp_demo(void)
{
	uint8_t out[64];
	assert(crypto_x25519_kp(x25519_prikey, curve25519_gx, out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, x25519_pubkey, sizeof(x25519_pubkey)) == 0);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int ecp256r1_kg_demo(void)
{
	uint8_t out[64];
	assert(crypto_ecc_kg(ecp256r1_prikey, out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, ecp256r1_pubkey, sizeof(ecp256r1_pubkey)) == 0);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int ecp256r1_kp_demo(void)
{
	uint8_t out[64];
	assert(crypto_ecc_kp(ecp256r1_prikey, ecp256r1_pubkey, out) == CRYPTO_RET_SUCCESS);
	assert(memcmp(out, ecp256r1_kp_result, sizeof(ecp256r1_kp_result)) == 0);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int ecp256r1_sign_demo(void)
{
	uint8_t out[64];
	assert(crypto_ecc_sign(ecp256r1_prikey, ecp256r1_msg, out) == CRYPTO_RET_SUCCESS);
	assert(crypto_ecc_verify(ecp256r1_pubkey, ecp256r1_msg, out) == CRYPTO_RET_SUCCESS);
	
	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int rsa_genkey_demo(void)
{
	crypto_rsa_key_t rsa_key;
	rsa_key.bits = 2048;
	crypto_rsa_gen_keypair(&rsa_key);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int sm2_genkey_demo(void)
{
	uint8_t prikey[32], pubkey[64];
	assert(crypto_sm2_gen_keypair(prikey, pubkey) == CRYPTO_RET_SUCCESS);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int ecp256r1_genkey_demo(void)
{
	uint8_t prikey[32], pubkey[64];
	assert(crypto_ecc_gen_keypair(prikey, pubkey) == CRYPTO_RET_SUCCESS);

	printf("Crypto Demo: Do %s() success.\n", __func__);
	return CRYPTO_RET_SUCCESS;
}

int main(int argc, char const *argv[])
{
	assert(md_demo() == CRYPTO_RET_SUCCESS);
	assert(cipher_demo() == CRYPTO_RET_SUCCESS);
	assert(hmac_demo() == CRYPTO_RET_SUCCESS);
	assert(prf_demo() == CRYPTO_RET_SUCCESS);

	assert(rsa_sign_demo() == CRYPTO_RET_SUCCESS);
	assert(rsa_enc_demo() == CRYPTO_RET_SUCCESS);
	
	assert(sm2_kg_demo() == CRYPTO_RET_SUCCESS);
	assert(sm2_kp_demo() == CRYPTO_RET_SUCCESS);
	assert(sm2_sign_demo() == CRYPTO_RET_SUCCESS);
	assert(sm2_enc_demo() == CRYPTO_RET_SUCCESS);

	assert(x25519_kg_demo() == CRYPTO_RET_SUCCESS);
	assert(x25519_kp_demo() == CRYPTO_RET_SUCCESS);

	assert(ecp256r1_kg_demo() == CRYPTO_RET_SUCCESS);
	assert(ecp256r1_kp_demo() == CRYPTO_RET_SUCCESS);
	assert(ecp256r1_sign_demo() == CRYPTO_RET_SUCCESS);
	
	assert(rsa_genkey_demo() == CRYPTO_RET_SUCCESS);
	assert(sm2_genkey_demo() == CRYPTO_RET_SUCCESS);
	assert(ecp256r1_genkey_demo() == CRYPTO_RET_SUCCESS);

	return CRYPTO_RET_SUCCESS;
}

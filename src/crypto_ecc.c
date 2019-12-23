#include "internal.h"

extern int X25519(uint8_t out_shared_key[32], 
					const uint8_t private_key[32], const uint8_t peer_public_value[32]);
extern void X25519_public_from_private(uint8_t out_public_value[32], const uint8_t private_key[32]);

int crypto_ecc_gen_keypair(uint8_t prikey[32], uint8_t pubkey[64])
{
	return crypto_ecc_gen_keypair_internal(NID_X9_62_prime256v1, prikey, pubkey);
}

int crypto_ecc_kg(uint8_t k[32], uint8_t r[64])
{
	return crypto_ecc_kg_internal(NID_X9_62_prime256v1, k, r);
}

int crypto_ecc_kp(uint8_t k[32], uint8_t p[64], uint8_t r[64])
{
	return crypto_ecc_kp_internal(NID_X9_62_prime256v1, k, p, r);
}

int crypto_ecc_sign(uint8_t prikey[32], uint8_t digest[32], uint8_t sign[64])
{
	return crypto_ecc_sign_internal(NID_X9_62_prime256v1, prikey, digest, sign);
}

int crypto_ecc_verify(uint8_t pubkey[64], uint8_t digest[32], uint8_t sign[64])
{
	return crypto_ecc_verify_internal(NID_X9_62_prime256v1, pubkey, digest, sign);
}

// x25519 为小端实现，外部数据通常为大端输入，待确认；
int crypto_x25519_kg(uint8_t k[32], uint8_t r[32])
{
	uint8_t temp_k[32];
	memcpy(temp_k, k, 32);
	tsr_swap_len(temp_k, 32);

	X25519_public_from_private(r, temp_k);
	tsr_swap_len(r, 32);

	return CRYPTO_RET_SUCCESS;
}

int crypto_x25519_kp(uint8_t k[32], uint8_t p[32], uint8_t r[32])
{
	uint8_t temp_k[32];
	uint8_t temp_p[32];
	memcpy(temp_k, k, 32);
	memcpy(temp_p, p, 32);

	tsr_swap_len(temp_k, 32);
	tsr_swap_len(temp_p, 32);

	X25519(r, temp_k, temp_p);
	tsr_swap_len(r, 32);

	return CRYPTO_RET_SUCCESS;
}
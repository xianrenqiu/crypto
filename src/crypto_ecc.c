#include "internal.h"

int crypto_ecc_gen_keypair(uint8_t algo, uint8_t prikey[32], uint8_t pubkey[64])
{

	return CRYPTO_RET_SUCCESS;
}

int crypto_ecc_kg(uint8_t algo, uint8_t k[32], uint8_t r[64])
{

	return CRYPTO_RET_SUCCESS;
}

int crypto_ecc_kp(uint8_t algo, uint8_t k[32], uint8_t p[64], uint8_t r[64])
{

	return CRYPTO_RET_SUCCESS;
}

int crypto_ecdsa_sign(uint8_t algo, uint8_t prikey[32], uint8_t digest[32], uint8_t sign[32])
{

	return CRYPTO_RET_SUCCESS;
}

int crypto_ecdsa_verify(uint8_t algo, uint8_t pubkey[32], uint8_t digest[32], uint8_t sign[32])
{

	return CRYPTO_RET_SUCCESS;
}


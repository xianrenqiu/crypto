#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_api.h"
#include "vector.h"
		
int md_demo(void)
{
	uint8_t digest[32];
	crypto_assert(crypto_md(MD_ALGO_SM3, msg, sizeof(msg), digest) == CRYPTO_RET_SUCCESS);
	crypto_assert(memcmp(digest, sm3_hash, 32) == 0);
	dump_buf("sm3(abc):", digest, 32);

	return CRYPTO_RET_SUCCESS;
}

int cipher_demo(void)
{

	return CRYPTO_RET_SUCCESS;
}

int hmac_demo(void)
{

	return CRYPTO_RET_SUCCESS;
}

int prf_demo(void)
{

	return CRYPTO_RET_SUCCESS;
}


int curve25519_kg_demo(void)
{

	return CRYPTO_RET_SUCCESS;
}

int curve25519_kp_demo(void)
{

	return CRYPTO_RET_SUCCESS;
}


int ecp256r1_kg_demo(void)
{

	return CRYPTO_RET_SUCCESS;
}

int ecp256r1_kp_demo(void)
{

	return CRYPTO_RET_SUCCESS;
}

int ecp256r1_sign_demo(void)
{

	return CRYPTO_RET_SUCCESS;
}


int rsa_sign_demo(void)
{

	return CRYPTO_RET_SUCCESS;
}

int rsa_enc_demo(void)
{

	return CRYPTO_RET_SUCCESS;
}


int sm2_sign_demo(void)
{

	return CRYPTO_RET_SUCCESS;
}

int sm2_enc_demo(void)
{

	return CRYPTO_RET_SUCCESS;
}

int main(int argc, char const *argv[])
{
	crypto_assert(md_demo() == CRYPTO_RET_SUCCESS);
	crypto_assert(cipher_demo() == CRYPTO_RET_SUCCESS);
	crypto_assert(hmac_demo() == CRYPTO_RET_SUCCESS);
	crypto_assert(prf_demo() == CRYPTO_RET_SUCCESS);

	crypto_assert(curve25519_kg_demo() == CRYPTO_RET_SUCCESS);
	crypto_assert(curve25519_kp_demo() == CRYPTO_RET_SUCCESS);

	crypto_assert(ecp256r1_kg_demo() == CRYPTO_RET_SUCCESS);
	crypto_assert(ecp256r1_kp_demo() == CRYPTO_RET_SUCCESS);
	crypto_assert(ecp256r1_sign_demo() == CRYPTO_RET_SUCCESS);
	
	crypto_assert(rsa_sign_demo() == CRYPTO_RET_SUCCESS);
	crypto_assert(rsa_enc_demo() == CRYPTO_RET_SUCCESS);
	
	crypto_assert(sm2_sign_demo() == CRYPTO_RET_SUCCESS);
	crypto_assert(sm2_enc_demo() == CRYPTO_RET_SUCCESS);

	return CRYPTO_RET_SUCCESS;
}

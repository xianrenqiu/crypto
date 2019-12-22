#include "internal.h"

int crypto_md(uint8_t algo, uint8_t *src, uint32_t len, uint8_t *digest)
{
	uint32_t size = 0;
	EVP_MD_CTX *ctx;
	assert((ctx = EVP_MD_CTX_new()) != 0);
	assert(EVP_DigestInit_ex(ctx, get_ssl_md(algo), NULL) == 1);
	assert(EVP_DigestUpdate(ctx, src, len) == 1);
	assert(EVP_DigestFinal_ex(ctx, digest, &size) == 1);
	EVP_MD_CTX_free(ctx);
	
	return CRYPTO_RET_SUCCESS;
}
#include "internal.h"

static const EVP_MD *get_ssl_md(uint8_t algo)
{
    switch (algo)
	{
        case MD_ALGO_SM3:
            return EVP_sm3();
            break;
    	case MD_ALGO_SHA1:
            return EVP_sha1();
    		break;
    	case MD_ALGO_SHA256:
            return EVP_sha256();
    		break;
    	case MD_ALGO_SHA384:
            return EVP_sha384();
    		break;
    	case MD_ALGO_SHA512:
            return EVP_sha512();
    		break;
	}
	
	return NULL;
}

void dump_buf(char *info, uint8_t *buf, uint32_t len)
{
    printf("%s[%d]", info, len);
    for (int i = 0; i < len; i++) {
        printf("%s%02X%s", i % 16 == 0 ? "\n     ":" ", 
                        buf[i], i == len - 1 ? "\n":"");
    }
}

int crypto_md(uint8_t algo, uint8_t *src, uint32_t len, uint8_t *digest)
{
	uint32_t size = 0;
	EVP_MD_CTX *ctx;
	crypto_assert((ctx = EVP_MD_CTX_new()) != 0);
	crypto_assert(EVP_DigestInit_ex(ctx, get_ssl_md(algo), NULL) == 1);
	crypto_assert(EVP_DigestUpdate(ctx, src, len) == 1);
	crypto_assert(EVP_DigestFinal_ex(ctx, digest, &size) == 1);
	EVP_MD_CTX_free(ctx);
	
	return CRYPTO_RET_SUCCESS;
}
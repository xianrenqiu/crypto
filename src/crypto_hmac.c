#include "internal.h"

int crypto_hmac(uint8_t algo, uint8_t *key, uint32_t keylen, uint8_t *src, uint32_t srclen, uint8_t *mac)
{
	uint32_t maclen;
	assert(HMAC(get_ssl_md(algo), key, keylen, src, srclen, mac, &maclen) != NULL);
    
    return CRYPTO_RET_SUCCESS;
}

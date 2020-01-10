#include "internal.h"

int crypto_random(uint8_t *buf, uint32_t size)
{

	RAND_bytes(buf, size);
	
	return CRYPTO_RET_SUCCESS;
}
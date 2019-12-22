#include "internal.h"

const EVP_MD *get_ssl_md(uint8_t algo)
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

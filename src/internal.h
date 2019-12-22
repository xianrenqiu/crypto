#ifndef __CRYPTO_INTERNAL_H__
#define __CRYPTO_INTERNAL_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <assert.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/sm2.h>
#include <openssl/hmac.h>

#include "crypto_api.h"
		
const EVP_MD *get_ssl_md(uint8_t algo);

#endif
#include "internal.h"

const EVP_CIPHER *crypto_get_ssl_cipher(uint8_t algo, uint8_t mode, uint32_t key_len)
{
	const EVP_CIPHER *cipher;

	if(algo == CIPHER_AES)
	{ 
		if(key_len == 16)
		{
			if(mode == CIPHER_MODE_ECB)
				cipher = EVP_aes_128_ecb();

			if(mode == CIPHER_MODE_CBC)
				cipher = EVP_aes_128_cbc();
		
			if(mode == CIPHER_MODE_CTR)
				cipher = EVP_aes_128_ctr();

			if(mode == CIPHER_MODE_GCM)
				cipher = EVP_aes_128_gcm();
		}

		if(key_len == 32)
		{
			if(mode == CIPHER_MODE_ECB)
				cipher = EVP_aes_256_ecb();

			if(mode == CIPHER_MODE_CBC)
				cipher = EVP_aes_256_cbc();
		
			if(mode == CIPHER_MODE_CTR)
				cipher = EVP_aes_256_ctr();

			if(mode == CIPHER_MODE_GCM)
				cipher = EVP_aes_256_gcm();
		}
	}

	if(algo == CIPHER_DES)
	{
		if(mode == CIPHER_MODE_ECB)
			cipher = EVP_des_ecb();

		if(mode == CIPHER_MODE_CBC)
			cipher = EVP_des_cbc();
	}

	if(algo == CIPHER_SM4)
	{ 
		if(mode == CIPHER_MODE_ECB)
			cipher = EVP_sms4_ecb();

		if(mode == CIPHER_MODE_CBC)
			cipher = EVP_sms4_cbc();
	
		if(mode == CIPHER_MODE_CTR)
			cipher = EVP_sms4_ctr();

		if(mode == CIPHER_MODE_GCM)
			cipher = EVP_sms4_gcm();
	}
	return cipher;
}

int crypto_cipher(uint8_t algo, uint8_t mode, uint8_t enc, uint8_t *key, uint32_t key_len, 
            uint8_t *iv, uint32_t iv_len, uint8_t *aad, uint32_t aad_len, uint8_t *src, uint32_t src_len, uint8_t *dst, uint8_t tag[16])
{
    int len = 0;
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = crypto_get_ssl_cipher(algo, mode, key_len);
    assert((ctx = EVP_CIPHER_CTX_new()) != 0);
    assert(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc) == 1);
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_NO_PADDING);

    if (mode == CIPHER_MODE_GCM)
        assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL) == 1);
    
    if (mode == CIPHER_MODE_GCM)
        assert(EVP_CipherUpdate(ctx, NULL, &len, aad, aad_len) == 1);

    if ((mode == CIPHER_MODE_GCM) && !enc)
        assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1);

    assert(EVP_CipherUpdate(ctx, dst, &len, src, src_len) == 1);
    assert(EVP_CipherFinal_ex(ctx, dst + len, &len) == 1);

    if ((mode == CIPHER_MODE_GCM) && (enc))
        assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1);

    EVP_CIPHER_CTX_free(ctx);
    
    return CRYPTO_RET_SUCCESS;
}

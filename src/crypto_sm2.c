#include "internal.h"

static int eckey_to_crypto_key(uint8_t prikey[32], uint8_t pubkey[64], EC_KEY **eckey)
{
	uint8_t temp[65];
	uint8_t *p = temp;
	assert(i2o_ECPublicKey(*eckey, &p) != 0);
	assert(temp[0] == 0x04);
	memmove(&pubkey[0], &temp[1], 64);
	
	EC_KEY_priv2oct(*eckey, prikey, 32);

	return CRYPTO_RET_SUCCESS;
}

static int crypto_key_to_eckey(uint8_t prikey[32], uint8_t pubkey[64], EC_KEY **eckey)
{
	if(pubkey)
	{
		uint8_t temp[65] = {0x04,};
		memcpy(temp + 1, pubkey, 64);
		uint8_t *p = temp;
		*eckey = o2i_ECPublicKey(eckey, (const uint8_t **)(&p), 65);
		assert(*eckey != 0);
	}
	
	if(prikey)
		EC_KEY_oct2priv(*eckey, prikey, 32);

	return CRYPTO_RET_SUCCESS;
}

static int crypto_key2pkey(uint8_t prikey[32], uint8_t pubkey[64], EVP_PKEY *pkey)
{
	EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    assert(ec_key != 0);
	EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
	assert(crypto_key_to_eckey(prikey, pubkey, &ec_key) == CRYPTO_RET_SUCCESS);
    assert(EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 0);

    return CRYPTO_RET_SUCCESS;
}

static int crypto_sigder2bin(uint8_t *der, size_t derlen, uint8_t sign[64])
{
 	BIGNUM *rr1 = BN_new();
    BIGNUM *ss1 = BN_new();
    ECDSA_SIG *s = ECDSA_SIG_new();
    uint8_t *p1 = der;
    d2i_ECDSA_SIG(&s, (const unsigned char **)&p1, derlen);
    ECDSA_SIG_get0((const ECDSA_SIG *)s,(const BIGNUM **)&rr1,(const BIGNUM **)&ss1);
    memset(sign, 0, 64);
    BN_bn2bin(rr1, sign + 32 - BN_num_bytes(rr1));
    BN_bn2bin(ss1, sign + 64 - BN_num_bytes(ss1));    
    ECDSA_SIG_free(s);

	return CRYPTO_RET_SUCCESS;
}

static int crypto_bin2sigder(uint8_t *der, size_t *derlen, uint8_t sign[64])
{
    BIGNUM *rr = BN_new();
    BIGNUM *ss = BN_new();
    BN_bin2bn(sign, 32, rr);
    BN_bin2bn(sign + 32, 32, ss);
    ECDSA_SIG *s = ECDSA_SIG_new();
    ECDSA_SIG_set0(s, rr, ss);
    uint8_t *p = der;
    *derlen = i2d_ECDSA_SIG(s, &p);
    ECDSA_SIG_free(s);

	return CRYPTO_RET_SUCCESS;
}

static int crypto_bin_to_sm2_cipher_der(EVP_PKEY_CTX *ctx, uint8_t *in, uint32_t len, uint8_t *der, size_t *derlen)
{
    const EC_GROUP *group;
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(EVP_PKEY_CTX_get0_pkey(ctx));
    group = EC_KEY_get0_group(ec_key);
    
    SM2CiphertextValue *cv = NULL;
    int total_len = 1 + len;
    uint8_t *buf_temp = malloc(total_len);
    uint8_t *p = buf_temp;
    
    buf_temp[0] = 0x04;
    memcpy(buf_temp + 1, in, 64);
    memcpy(buf_temp + 65, in + 64, len - 96);
    memcpy(buf_temp + 1 + (len - 32), in + (len - 32), 32);

    cv = o2i_SM2CiphertextValue(group, EVP_sm3(), &cv, (const unsigned char **)&p, total_len);
    assert(cv != NULL);

    *derlen = i2d_SM2CiphertextValue(cv, &der);
    assert(*derlen >= 0);

    free(buf_temp);

	return CRYPTO_RET_SUCCESS;
}

static int sm2_cipher_der_to_crypto_bin(EVP_PKEY_CTX *ctx, uint8_t *der, uint32_t der_len, uint8_t *out, uint32_t *outlen)
{
    const EC_GROUP *group;
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(EVP_PKEY_CTX_get0_pkey(ctx));
    group = EC_KEY_get0_group(ec_key);

    SM2CiphertextValue *cv = NULL;
    uint8_t *p = der;
    if (!(cv = d2i_SM2CiphertextValue(NULL, (const unsigned char **)&p, (long)der_len)))
        return 0;
    
    uint8_t *buf_temp = malloc(der_len);
    p = buf_temp;
    int total_len = i2o_SM2CiphertextValue(group, cv, &p);
    *outlen = total_len - 1;

    memcpy(out, buf_temp + 1, 64);
    memcpy(out + 64, buf_temp + 1 + 64, total_len - 96);
    memcpy(out + (total_len - 32), buf_temp + 1 + (total_len - 32), 32);
    free(buf_temp);

	return CRYPTO_RET_SUCCESS;
}

int crypto_sm2_gen_keypair(uint8_t prikey[32], uint8_t pubkey[64])
{
	EVP_PKEY *pkey = EVP_PKEY_new();
	EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    assert(ec_key != NULL);

	EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
    assert(EC_KEY_generate_key(ec_key) != 0);
    assert(EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 0);
	assert(eckey_to_crypto_key(pubkey, prikey, &ec_key) == CRYPTO_RET_SUCCESS);

	EVP_PKEY_free(pkey);

	return CRYPTO_RET_SUCCESS;
}

int crypto_sm2_kg(uint8_t k[32], uint8_t r[64])
{
	const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    int filed = EC_METHOD_get_field_type(EC_GROUP_method_of(group));

    BN_CTX *bn_ctx;
    BIGNUM *x1, *y1, *ec_k;
    bn_ctx = BN_CTX_new();
    BN_CTX_start(bn_ctx);
    x1 = BN_CTX_get(bn_ctx);
    y1 = BN_CTX_get(bn_ctx);
    ec_k = BN_CTX_get(bn_ctx);
    BN_bin2bn((uint8_t *)k, 32, ec_k);
    
	EC_POINT *ec_r = EC_POINT_new(group);
    assert(EC_POINT_mul(group, ec_r, ec_k, NULL, NULL, NULL) == 1);
        
    if (filed == NID_X9_62_prime_field)
        assert(EC_POINT_get_affine_coordinates_GFp(group, ec_r, x1, y1, bn_ctx) == 1);
    else
        assert(EC_POINT_get_affine_coordinates_GF2m(group, ec_r, x1, y1, bn_ctx) == 1);
    
    BN_bn2bin(x1, r);
    BN_bn2bin(y1, r + 32);

    BN_CTX_free(bn_ctx);
    EC_POINT_free(ec_r);
	EC_GROUP_free((EC_GROUP *)group);

	return CRYPTO_RET_SUCCESS;
}

int crypto_sm2_kp(uint8_t k[32], uint8_t p[64], uint8_t r[64])
{
	const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    int filed = EC_METHOD_get_field_type(EC_GROUP_method_of(group));

    BN_CTX *bn_ctx;
    BIGNUM *x1, *y1, *x2, *y2, *ec_k;
    bn_ctx = BN_CTX_new();
    BN_CTX_start(bn_ctx);
    x1 = BN_CTX_get(bn_ctx);
    y1 = BN_CTX_get(bn_ctx);
    x2 = BN_CTX_get(bn_ctx);
    y2 = BN_CTX_get(bn_ctx);
    ec_k = BN_CTX_get(bn_ctx);

    BN_bin2bn((uint8_t *)k, 32, ec_k);
    BN_bin2bn((uint8_t *)p, 32, x1);
    BN_bin2bn((uint8_t *)p + 32, 32, y1);
    
	EC_POINT *ec_r = EC_POINT_new(group);
	EC_POINT *ec_p = EC_POINT_new(group);

    if (filed == NID_X9_62_prime_field)
        assert(EC_POINT_set_affine_coordinates_GFp(group, ec_p, x1, y1, bn_ctx) == 1);
    else
        assert(EC_POINT_set_affine_coordinates_GF2m(group, ec_p, x1, y1, bn_ctx) == 1);
    
    assert(EC_POINT_mul(group, ec_r, NULL, ec_p, ec_k, NULL) == 1);
        
    if (filed == NID_X9_62_prime_field)
        assert(EC_POINT_get_affine_coordinates_GFp(group, ec_r, x2, y2, bn_ctx) == 1);
    else
        assert(EC_POINT_get_affine_coordinates_GF2m(group, ec_r, x2, y2, bn_ctx) == 1);
    
    BN_bn2bin(x2, r);
    BN_bn2bin(y2, r + 32);
    
    BN_CTX_free(bn_ctx);
    EC_POINT_free(ec_r);
    EC_POINT_free(ec_p);
	EC_GROUP_free((EC_GROUP *)group);

	return CRYPTO_RET_SUCCESS;
}

int crypto_sm2_sign(uint8_t prikey[32], uint8_t digest[32], uint8_t sign[64])
{
	uint8_t sig_der[128];
	size_t sig_der_size = 128;

    EVP_PKEY *pkey = EVP_PKEY_new();
    assert(crypto_key2pkey(prikey, NULL, pkey) == CRYPTO_RET_SUCCESS);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    assert(EVP_PKEY_sign_init(ctx) == 1);
    assert(EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme) == 1);
    assert(EVP_PKEY_sign(ctx, sig_der, &sig_der_size, digest, 32) == 1);

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);

	return crypto_sigder2bin(sig_der, sig_der_size, sign);
}

int crypto_sm2_verify(uint8_t pubkey[64], uint8_t digest[32], uint8_t sign[64])
{
	uint8_t sig_der[128];
	size_t sig_der_size = 128;

    EVP_PKEY *pkey = EVP_PKEY_new();
    assert(crypto_key2pkey(NULL, pubkey, pkey) == CRYPTO_RET_SUCCESS);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	assert(crypto_bin2sigder(sig_der, &sig_der_size, sign) == CRYPTO_RET_SUCCESS);
	assert(EVP_PKEY_verify_init(ctx) == 1);
	assert(EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme) == 1);
	assert(EVP_PKEY_verify(ctx, sig_der, sig_der_size, digest, 32) == 1);

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);

	return CRYPTO_RET_SUCCESS;
}

int crypto_sm2_encrypt(uint8_t pubkey[64], uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t *outlen)
{
	size_t sm2_cipher_out_len = 256 + inlen;
	uint8_t *sm2_cipher_out = malloc(sm2_cipher_out_len);

    EVP_PKEY *pkey = EVP_PKEY_new();
    assert(crypto_key2pkey(NULL, pubkey, pkey) == CRYPTO_RET_SUCCESS);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    assert(EVP_PKEY_encrypt_init(ctx) == 1);
    assert(EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme) == 1);
    assert(EVP_PKEY_CTX_set_ec_encrypt_param(ctx, NID_sm3) == 1);
    assert(EVP_PKEY_encrypt(ctx, sm2_cipher_out, &sm2_cipher_out_len, in, (size_t)inlen) == 1);
    assert(sm2_cipher_der_to_crypto_bin(ctx, sm2_cipher_out, sm2_cipher_out_len, out, outlen) == CRYPTO_RET_SUCCESS);

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);

	return CRYPTO_RET_SUCCESS;
}

int crypto_sm2_decrypt(uint8_t prikey[32], uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t *outlen)
{
    size_t tlen = *outlen;
	size_t sm2_cipher_out_len = 256 + inlen;
	uint8_t *sm2_cipher_out = malloc(sm2_cipher_out_len);

    EVP_PKEY *pkey = EVP_PKEY_new();
    assert(crypto_key2pkey(prikey, NULL, pkey) == CRYPTO_RET_SUCCESS);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    assert(crypto_bin_to_sm2_cipher_der(ctx, in, inlen, sm2_cipher_out, &sm2_cipher_out_len) == CRYPTO_RET_SUCCESS);

    assert(EVP_PKEY_decrypt_init(ctx) == 1);
    assert(EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme) == 1);
    assert(EVP_PKEY_CTX_set_ec_encrypt_param(ctx, NID_sm3) == 1);
    assert(EVP_PKEY_decrypt(ctx, out, &tlen, sm2_cipher_out, sm2_cipher_out_len) == 1);
    *outlen = tlen;

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);

	return CRYPTO_RET_SUCCESS;
}


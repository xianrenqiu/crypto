#ifndef __DEMO_H__
#define __DEMO_H__

#include <stdint.h>

uint8_t msg[3] =
{
	0x61, 0x62, 0x63
};

uint8_t sha1_hash[] =
{
	0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 
    0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
	0x9c, 0xd0, 0xd8, 0x9d,
};

uint8_t md5_hash[] =
{
	0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 
    0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
};

uint8_t sha256_hash[] =
{
	0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
	0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 
	0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};
    
uint8_t sm3_hash[] =
{
	0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 
    0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
	0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 
	0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0,
};

uint8_t sha384_hash[] =
{
    0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 
    0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07, 
    0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63, 
    0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED, 
    0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23, 
    0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7
};

uint8_t sha512_hash[] =
{
    0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA, 
    0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31, 
    0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2, 
    0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A, 
    0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8, 
    0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD, 
    0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E, 
    0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F
};

uint8_t gcm_iv[12] =
{ 
    0x21, 0x22, 0x8F, 0x7D, 0x26, 0x04, 0xB3, 0x93, 0xB0, 0xD0, 0x0D, 0x3F
};

uint8_t gcm_key[16] =
{
    0x22, 0xCB, 0xDE, 0x92, 0xBD, 0xEE, 0x25, 0x63, 0xF0, 0x82, 0xE5, 0x5D, 0xC5, 0x73, 0x5F, 0x46
};

uint8_t gcm_aad[13] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00, 0x10
};

uint8_t gcm_in[16] =
{
    0x14, 0x00, 0x00, 0x0C, 0xA4, 0x99, 0x94, 0xBC, 0x08, 0x1C, 0x87, 0xA5, 0x90, 0x19, 0xD9, 0x3D
};

uint8_t gcm_rst[16] = 
{
	0x40, 0xC6, 0x19, 0x6C, 0xC5, 0xC4, 0x78, 0xCD, 
	0x54, 0xCD, 0x7D, 0x1D, 0x68, 0xA7, 0x5B, 0xA3
};

uint8_t gcm_tag[16] = 
{
	0xA3, 0x02, 0xB2, 0xEA, 0x8B, 0xB6, 0x57, 0xFE, 
	0x9D, 0x73, 0xFD, 0xF4, 0xDB, 0x49, 0x6C, 0x1A
};

uint8_t sm2_msg[] = {    
    0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 
    0x6F, 0x6E, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64
};

uint8_t sm2_prikey[] = {    
    0x39, 0x45, 0x20, 0x8F, 0x7B, 0x21, 0x44, 0xB1, 
    0x3F, 0x36, 0xE3, 0x8A, 0xC6, 0xD3, 0x9F, 0x95,
    0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xB5, 0x1A, 
    0x42, 0xFB, 0x81, 0xEF, 0x4D, 0xF7, 0xC5, 0xB8
};

uint8_t sm2_pubkey[] = {    
    0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 
    0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6, 
    0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 
    0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
    0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 
    0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60, 
    0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 
    0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13
};

uint8_t sm2_ctx_ok[] = {   
    // c1 
    0x04, 0xEB, 0xFC, 0x71, 0x8E, 0x8D, 0x17, 0x98, 
    0x62, 0x04, 0x32, 0x26, 0x8E, 0x77, 0xFE, 0xB6, 
    0x41, 0x5E, 0x2E, 0xDE, 0x0E, 0x07, 0x3C, 0x0F, 
    0x4F, 0x64, 0x0E, 0xCD, 0x2E, 0x14, 0x9A, 0x73,
    0xE8, 0x58, 0xF9, 0xD8, 0x1E, 0x54, 0x30, 0xA5, 
    0x7B, 0x36, 0xDA, 0xAB, 0x8F, 0x95, 0x0A, 0x3C, 
    0x64, 0xE6, 0xEE, 0x6A, 0x63, 0x09, 0x4D, 0x99, 
    0x28, 0x3A, 0xFF, 0x76, 0x7E, 0x12, 0x4D, 0xF0,

    // c2
    0x21, 0x88, 0x6C, 0xA9, 0x89, 0xCA, 0x9C, 0x7D, 
    0x58, 0x08, 0x73, 0x07, 0xCA, 0x93, 0x09, 0x2D, 0x65, 0x1E, 0xFA,

    // c3
    0x59, 0x98, 0x3C, 0x18, 0xF8, 0x09, 0xE2, 0x62, 
    0x92, 0x3C, 0x53, 0xAE, 0xC2, 0x95, 0xD3, 0x03,
    0x83, 0xB5, 0x4E, 0x39, 0xD6, 0x09, 0xD1, 0x60, 
    0xAF, 0xCB, 0x19, 0x08, 0xD0, 0xBD, 0x87, 0x66
};

uint8_t rsa2048_e[256] = {0x01, 0x00, 0x01};

uint8_t rsa2048_digest[32] = 
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x54, 0x90, 0xFC, 0x4D, 0xF4, 0x6A, 0xA3, 0x3F, 0xC0, 0x8B, 0x40, 0x31, 0x6D, 0x2D, 0x5D, 0x1F, 
	0x42, 0x66, 0xFB, 0xF5, 0x62, 0xB8, 0x08, 0xCA, 0x68, 0x51, 0xF6, 0xB0, 0x21, 0x78, 0x50, 0x75,
};

uint8_t rsa2048_signature[] = {
	0x74, 0x3F, 0x86, 0x35, 0xAC, 0xC6, 0x37, 0xD9, 0x41, 0xD5, 0x84, 0xE9, 0xA3, 0x39, 0xB5, 0x31, 
	0x0F, 0x46, 0x03, 0x8A, 0x23, 0x03, 0x1C, 0x70, 0xD0, 0x3D, 0xFF, 0xBE, 0x20, 0xA9, 0xBB, 0x60, 
	0x7E, 0xE3, 0xBC, 0xBB, 0x84, 0x49, 0x4A, 0xB0, 0x27, 0x19, 0x10, 0xB9, 0xEC, 0xD3, 0xDC, 0x03, 
	0xD9, 0x12, 0x3D, 0x69, 0xB4, 0x0B, 0x3B, 0xB3, 0x52, 0x5D, 0x73, 0x35, 0xA8, 0x9D, 0x67, 0x62, 
	0x9D, 0xEC, 0x2F, 0x38, 0x08, 0x25, 0xAF, 0xA3, 0x3F, 0x5D, 0x46, 0xCD, 0x81, 0xDC, 0x32, 0x8B, 
	0xB2, 0x06, 0x13, 0x46, 0x23, 0xF9, 0xBA, 0x9A, 0xF9, 0x21, 0x4E, 0x06, 0x92, 0xC0, 0xF2, 0x13, 
	0xA7, 0x6E, 0x9D, 0xA0, 0x54, 0x49, 0x64, 0x4B, 0xED, 0x4C, 0x65, 0xFE, 0xC0, 0x62, 0xF6, 0x82, 
	0x0B, 0x53, 0x81, 0x4E, 0xE8, 0xD5, 0xCA, 0x3D, 0xE9, 0x5E, 0xD6, 0xF9, 0x42, 0xBB, 0xAA, 0x60, 
	0x12, 0x88, 0x44, 0x5E, 0x25, 0xF5, 0x9D, 0xF7, 0xAC, 0x33, 0xFD, 0xBE, 0x65, 0xE4, 0x6D, 0x3D, 
	0x45, 0x8D, 0x9C, 0xC2, 0x47, 0x4B, 0x9E, 0x74, 0x35, 0xDD, 0x97, 0xA2, 0x65, 0x30, 0xD1, 0x80, 
	0x8A, 0xFF, 0x27, 0x32, 0x66, 0x9F, 0xF3, 0x4F, 0x4B, 0xEA, 0x53, 0x86, 0x67, 0x24, 0xD0, 0x3B, 
	0xBD, 0x70, 0x3C, 0xF2, 0x6B, 0x4F, 0xBE, 0xC5, 0xEC, 0x51, 0xA9, 0x01, 0xC4, 0xC9, 0x6B, 0x8C, 
	0x3C, 0xDA, 0x57, 0x26, 0x90, 0x2A, 0xD0, 0xB4, 0x6E, 0x25, 0xC8, 0xF5, 0xC7, 0xE6, 0xD0, 0x87, 
	0xB9, 0x2F, 0x45, 0xD0, 0xEC, 0x23, 0x8E, 0xBF, 0x68, 0x0D, 0x4F, 0xF2, 0x58, 0x08, 0x9D, 0x22, 
	0xD8, 0x2E, 0x88, 0xBD, 0x6F, 0x93, 0x7A, 0x13, 0x52, 0x32, 0xF6, 0xC5, 0x13, 0x9A, 0x02, 0x5E, 
	0xF0, 0x93, 0xC9, 0x64, 0x3F, 0x70, 0x01, 0x28, 0x2F, 0x95, 0x12, 0x0F, 0x90, 0xB7, 0x24, 0x61,
};
uint8_t rsa2048_p[] = {
	0xB4, 0xF8, 0xC7, 0xF0, 0xC7, 0x0A, 0xC0, 0x41, 0xA7, 0x48, 0x22, 0x48, 0xCA, 0xF1, 0xFC, 0x64, 
	0x0A, 0x9F, 0xEB, 0x71, 0xC3, 0x1B, 0xD2, 0x34, 0xAE, 0x62, 0xD7, 0x05, 0xFF, 0xF1, 0xA0, 0xBD, 
	0xBC, 0x58, 0xCE, 0xE1, 0x5E, 0xFC, 0xB9, 0x0F, 0xAD, 0x2E, 0x6C, 0xA8, 0xD7, 0x6B, 0xE1, 0xBD, 
	0xD1, 0xF4, 0x80, 0x3D, 0xF1, 0x90, 0xD4, 0x5E, 0xCB, 0x9F, 0x8E, 0x4B, 0x4A, 0x62, 0xBE, 0x0E, 
	0x10, 0x88, 0x4F, 0xBF, 0x12, 0xFA, 0xC3, 0xEC, 0x6E, 0xEA, 0x2E, 0x4A, 0x8E, 0x18, 0x76, 0x9C, 
	0x81, 0x66, 0xCB, 0xE2, 0x97, 0x9E, 0x63, 0xC4, 0x3E, 0x80, 0x7A, 0x40, 0x1B, 0x11, 0x88, 0x91, 
	0x6A, 0x21, 0xC3, 0x61, 0x99, 0x1D, 0xD6, 0x31, 0x21, 0x15, 0xE1, 0x07, 0xA7, 0x0F, 0xB2, 0x58, 
	0x52, 0x8D, 0x45, 0x37, 0x6D, 0x5B, 0x78, 0xBE, 0x40, 0x9C, 0x12, 0xBB, 0x29, 0x16, 0xF6, 0x2B,
};
uint8_t rsa2048_q[] = {
	0xB4, 0xC6, 0x13, 0x8A, 0x1F, 0xDB, 0x2B, 0xC6, 0x7B, 0x3A, 0x4C, 0x82, 0xD7, 0x1A, 0xDF, 0x56, 
	0xA4, 0x8F, 0x56, 0xD6, 0x57, 0x58, 0xEE, 0xFE, 0x41, 0xE9, 0xA5, 0xDE, 0xAC, 0xBB, 0x78, 0x88, 
	0x39, 0xD1, 0xE1, 0x39, 0x77, 0x8D, 0x8F, 0xC6, 0xC6, 0xB3, 0x65, 0x48, 0x6D, 0xBD, 0xB7, 0x09, 
	0xF8, 0x60, 0xC2, 0xB0, 0xD6, 0x5D, 0x6B, 0xAA, 0x32, 0x8B, 0x3B, 0xDA, 0x10, 0x23, 0x99, 0x83, 
	0xAA, 0x4D, 0x49, 0x74, 0x0B, 0xEB, 0x23, 0x75, 0xEC, 0xA3, 0x16, 0xF0, 0xCD, 0x31, 0x5F, 0xE2, 
	0x55, 0xED, 0x04, 0x02, 0xED, 0x9A, 0x95, 0x31, 0x9A, 0x6F, 0x25, 0x24, 0x1A, 0x6A, 0x86, 0x50, 
	0x40, 0xD2, 0xC3, 0x14, 0x93, 0x0C, 0xE1, 0x2B, 0x24, 0xA2, 0xD8, 0x53, 0xAE, 0x90, 0xCE, 0x38, 
	0xF3, 0xD0, 0x94, 0xA5, 0x54, 0x26, 0x65, 0xED, 0xB1, 0x2F, 0xDC, 0x95, 0x81, 0xA6, 0x3D, 0xD1,
};
uint8_t rsa2048_dmp1[] = {
	0x0B, 0xA7, 0x29, 0x58, 0xBB, 0xB8, 0x59, 0x80, 0xE0, 0xC0, 0xA8, 0x54, 0x7F, 0x9C, 0xED, 0x5F, 
	0x93, 0xBF, 0x90, 0x6D, 0x96, 0xDE, 0xA7, 0xBE, 0x74, 0xAC, 0x30, 0xA4, 0x56, 0x42, 0xBC, 0xD2, 
	0xFA, 0xD9, 0xCD, 0x18, 0x7E, 0x01, 0x4F, 0xF9, 0x4E, 0x71, 0x7A, 0xD5, 0xB4, 0x69, 0x61, 0xF3, 
	0xD3, 0x1D, 0x27, 0x54, 0xD5, 0xC5, 0x39, 0xA7, 0x90, 0xFD, 0x09, 0x30, 0x97, 0xED, 0x9B, 0xC7, 
	0x54, 0x11, 0x32, 0xF1, 0x5E, 0xCB, 0x7E, 0xEA, 0x2E, 0x8A, 0x2D, 0xC8, 0xE7, 0x35, 0x74, 0x0D, 
	0xC7, 0xD7, 0x52, 0xB1, 0x98, 0x89, 0xBE, 0x6A, 0xD8, 0x8B, 0x75, 0x53, 0xC3, 0x6A, 0x71, 0x9C, 
	0xCB, 0x74, 0xB9, 0x1C, 0x03, 0xBC, 0x04, 0x1A, 0xCD, 0xC2, 0x96, 0xE6, 0xE3, 0x3F, 0x03, 0x80, 
	0xE4, 0x6F, 0xEC, 0x51, 0x11, 0x5D, 0x9E, 0x7C, 0xC1, 0xB4, 0x4B, 0x10, 0x7A, 0x28, 0xDC, 0x59,
};
uint8_t rsa2048_dmq1[] = {
	0x10, 0x55, 0xBD, 0xBA, 0x43, 0x7A, 0xA8, 0x8F, 0xFC, 0xDE, 0x9D, 0xBF, 0x4C, 0xF4, 0xAE, 0xAD, 
	0xC3, 0x9C, 0xF8, 0x39, 0xD2, 0x16, 0xC5, 0x31, 0xD0, 0x7E, 0xEE, 0x70, 0x1A, 0xA7, 0xAE, 0x12, 
	0x91, 0x36, 0xF7, 0xE5, 0x1B, 0x7A, 0x7D, 0x3D, 0x77, 0x03, 0x0A, 0xE9, 0xEA, 0x90, 0xB4, 0x13, 
	0x80, 0x90, 0x2D, 0xC7, 0x90, 0xF7, 0x4C, 0x1D, 0x4B, 0x07, 0xED, 0xD6, 0x9C, 0x92, 0xBA, 0xF2, 
	0x7C, 0xD7, 0x13, 0x06, 0x1B, 0x75, 0x99, 0xF4, 0xB3, 0xF7, 0x60, 0xC1, 0x4D, 0xA9, 0x62, 0x82, 
	0xAF, 0x45, 0x05, 0x91, 0xC6, 0x2A, 0xAB, 0xC4, 0x99, 0xB1, 0xE5, 0x67, 0x47, 0xC3, 0xCC, 0x73, 
	0x40, 0x08, 0x4B, 0x7C, 0x76, 0x75, 0x39, 0x7B, 0x8E, 0x89, 0xF0, 0x86, 0x4F, 0x45, 0xE2, 0x7C, 
	0x9E, 0xFB, 0x80, 0x13, 0x18, 0x71, 0x87, 0xD0, 0x5C, 0xAC, 0x78, 0x80, 0x42, 0x00, 0xE5, 0xA1,
};

uint8_t rsa2048_iqmp[] = {
	0x81, 0x7B, 0x08, 0x71, 0x76, 0xEE, 0x53, 0xA3, 0x05, 0x34, 0xC9, 0xA1, 0xCE, 0x29, 0xC9, 0x02, 
	0x2F, 0xE3, 0xCA, 0x7B, 0xF7, 0x96, 0x1E, 0xED, 0x55, 0xAB, 0x3E, 0x6A, 0xE9, 0x3D, 0x89, 0xE4, 
	0x67, 0xC1, 0x51, 0x6F, 0xF5, 0xBA, 0x02, 0xA8, 0x9B, 0x8C, 0xF0, 0x49, 0x39, 0x0B, 0x19, 0x25,
	0xEA, 0xA9, 0xCC, 0xD4, 0x02, 0x3B, 0xC8, 0x55, 0xD5, 0x82, 0x90, 0x47, 0xF7, 0xC5, 0x2D, 0x55, 
	0x42, 0xC6, 0x5D, 0xAD, 0xFF, 0x69, 0x44, 0xF3, 0x16, 0xB3, 0xA7, 0x71, 0x1B, 0xF4, 0x21, 0x61, 
	0x5C, 0x80, 0x04, 0x79, 0x41, 0xD3, 0xE7, 0x1F, 0x1A, 0xD2, 0xE8, 0x5C, 0x7F, 0x61, 0xE3, 0x31, 
	0xD1, 0xF3, 0x31, 0xFC, 0x2B, 0x99, 0x76, 0x33, 0xA3, 0x5F, 0xA7, 0x64, 0x92, 0x62, 0x38, 0x6E, 
	0xB7, 0x36, 0x56, 0x42, 0x98, 0xE4, 0x93, 0xDE, 0x63, 0xE5, 0x98, 0x59, 0x66, 0x7B, 0x89, 0xF2,
};

uint8_t rsa2048_d[] = {
	0x56, 0x5E, 0xCE, 0x79, 0x7A, 0x45, 0x72, 0x79, 0x78, 0x7B, 0x96, 0x66, 0x82, 0x10, 0x01, 0x5C, 
	0x50, 0x40, 0x1A, 0x3E, 0x27, 0x69, 0x1C, 0x93, 0x9D, 0x5D, 0x5F, 0x05, 0xF1, 0x1D, 0x30, 0x84, 
	0xCD, 0x40, 0x7A, 0xD2, 0x1F, 0x90, 0x54, 0x31, 0xEA, 0xB8, 0xEC, 0x91, 0x17, 0x6F, 0x45, 0xC9, 
	0x02, 0xCD, 0xA8, 0x00, 0x30, 0xC1, 0xBD, 0xD1, 0xB9, 0xFB, 0xB9, 0x15, 0xC5, 0x6B, 0xD7, 0xDB, 
	0x38, 0x9F, 0xEF, 0x05, 0x38, 0xFA, 0x76, 0x76, 0x96, 0x40, 0xCE, 0x36, 0x37, 0x2D, 0xDC, 0x51, 
	0xFA, 0x87, 0xC3, 0xA0, 0x26, 0xB3, 0x79, 0x05, 0x2A, 0xA0, 0xCE, 0xE7, 0x5F, 0x76, 0xDD, 0x5B, 
	0x6E, 0x57, 0x84, 0x81, 0xE4, 0x38, 0xB9, 0x24, 0xBE, 0xC2, 0xB9, 0xAC, 0xDC, 0xEC, 0xB4, 0xD0, 
	0x28, 0x0D, 0xE4, 0x58, 0xF0, 0x25, 0x3D, 0x5A, 0xF5, 0x6E, 0x1A, 0xC3, 0xE6, 0x78, 0x20, 0x14, 
	0x7B, 0x8E, 0x7B, 0xCC, 0x4F, 0x50, 0x30, 0x0B, 0x25, 0x94, 0xE8, 0x4E, 0x7F, 0x3B, 0x73, 0x2A, 
	0x4C, 0xDB, 0xFD, 0x3C, 0xB8, 0x3A, 0x3C, 0xB5, 0x75, 0x65, 0xD3, 0x65, 0x25, 0x72, 0xDF, 0x64, 
	0x81, 0xC3, 0x72, 0xA8, 0x7E, 0x93, 0x51, 0x9D, 0x5B, 0x5A, 0xB0, 0xEC, 0x3B, 0x3E, 0x03, 0x5E, 
	0x13, 0x9B, 0x60, 0xE4, 0x97, 0xB4, 0x7E, 0xF5, 0xDE, 0xE0, 0x06, 0x00, 0x8E, 0x84, 0x83, 0x76, 
	0x86, 0x17, 0x7E, 0x19, 0xCD, 0xF8, 0xF4, 0xA3, 0xE7, 0x68, 0xB9, 0xF9, 0xD2, 0x9E, 0xFC, 0x04, 
	0xB8, 0x71, 0x64, 0xE1, 0x2D, 0x39, 0x41, 0x51, 0xCE, 0x39, 0x86, 0x4A, 0x6D, 0x0F, 0x97, 0x17, 
	0x3B, 0xF4, 0x20, 0xD0, 0x34, 0xCE, 0x9F, 0xD9, 0x5A, 0xE3, 0x03, 0x40, 0x89, 0x97, 0x68, 0x0A, 
	0x9C, 0x1A, 0x00, 0x10, 0x5B, 0x6E, 0x54, 0x6E, 0x07, 0x8F, 0x9F, 0x4D, 0xC1, 0x50, 0xB8, 0xC1,
};

uint8_t rsa2048_n[] = {
	0x7F, 0xCA, 0xF2, 0xD0, 0x0B, 0xA5, 0x38, 0x0B, 0x40, 0xA8, 0x04, 0x5B, 0xBC, 0x64, 0xC4, 0xE6, 
	0x67, 0xE5, 0x56, 0x00, 0x5B, 0x38, 0x6B, 0x86, 0xF6, 0xCB, 0x06, 0xD9, 0xC0, 0x6B, 0x76, 0x8C, 
	0xE4, 0x93, 0xDD, 0x62, 0x47, 0x26, 0x27, 0xC0, 0xD5, 0xAC, 0xE2, 0xC1, 0x68, 0x46, 0xE9, 0x26, 
	0x34, 0xD1, 0x48, 0x5B, 0xF8, 0x03, 0x22, 0xC7, 0x41, 0x4E, 0x4E, 0xC5, 0xC4, 0x9E, 0x58, 0x24, 
	0xFD, 0xF2, 0xFB, 0x7C, 0xB0, 0x34, 0x9D, 0x29, 0xF9, 0xAF, 0x69, 0x96, 0x43, 0xE0, 0x29, 0xCC, 
	0x00, 0x1A, 0x40, 0x6E, 0x1A, 0x42, 0x9A, 0x22, 0x13, 0x03, 0xBE, 0x11, 0x5A, 0x35, 0x74, 0x43, 
	0x6F, 0x28, 0x76, 0x3C, 0x22, 0x81, 0xEE, 0xB7, 0x4D, 0xD9, 0x00, 0x84, 0x8D, 0x4E, 0xCF, 0x01, 
	0x7F, 0x03, 0x10, 0xC3, 0xF9, 0xEE, 0xB7, 0x5A, 0x1E, 0x97, 0x72, 0xE5, 0xD3, 0x61, 0xC5, 0x32, 
	0x39, 0xA4, 0x5C, 0x2F, 0x1A, 0x86, 0x29, 0x97, 0x83, 0x16, 0x19, 0x99, 0xEA, 0x1E, 0xFF, 0x33, 
	0xE7, 0xAF, 0xF2, 0x7E, 0x3B, 0x4D, 0x13, 0xDE, 0x3B, 0xE7, 0x24, 0x5B, 0x20, 0x32, 0xBD, 0x18, 
	0xE3, 0x3E, 0x83, 0xA5, 0xE9, 0xBD, 0x22, 0x5C, 0x7C, 0x81, 0x68, 0x31, 0x7E, 0x5E, 0xB9, 0xDF, 
	0xEE, 0x73, 0xC1, 0xDF, 0xFA, 0x29, 0x4F, 0x3F, 0xC2, 0x50, 0x39, 0x20, 0xE2, 0x1B, 0xA3, 0xBF, 
	0xF9, 0xAE, 0x72, 0xE3, 0x80, 0x79, 0x19, 0xEF, 0xEF, 0x21, 0x80, 0x4A, 0x66, 0x02, 0x26, 0xE0, 
	0x3D, 0xB2, 0x18, 0x92, 0x75, 0x04, 0xE6, 0xDA, 0x73, 0x1B, 0x98, 0xB5, 0xC1, 0x3C, 0x0B, 0x68, 
	0x2F, 0xF9, 0x53, 0xA3, 0x57, 0xE9, 0x51, 0x89, 0x34, 0xF9, 0x7A, 0xA5, 0x5A, 0x3A, 0x27, 0xD4, 
	0x01, 0xAC, 0x9A, 0xB4, 0x8F, 0xD7, 0x79, 0xD4, 0xF7, 0xC2, 0x55, 0x8D, 0x4F, 0x49, 0x38, 0x1B,
};

uint8_t ecp256r1_g[32] = 
{
	0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, 
	0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
	0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 
	0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
};

uint8_t ecp256r1_d[32] = 
{
	0x5E, 0x92, 0x6F, 0x2D, 0x95, 0x83, 0x69, 0x3C, 0xB3, 0xF2, 0xDD, 0x5E, 0x77, 0x60, 0xAF, 0x25,
	0x23, 0xC4, 0x34, 0xF2, 0xD5, 0x9E, 0x1A, 0xCF, 0x24, 0x3D, 0x99, 0xC7, 0xF0, 0x9A, 0x5D, 0x51
};

uint8_t ecp256r1_q[32] = 
{
	0x30, 0x8F, 0xF0, 0x2E, 0x14, 0x38, 0x86, 0xD1, 0x12, 0xFA, 0xAB, 0x10, 0xE0, 0x82, 0xC5, 0x33,
	0x82, 0x7C, 0xD6, 0xE9, 0xA5, 0x16, 0x3A, 0x71, 0x81, 0xE0, 0x5B, 0x00, 0x17, 0xD6, 0xFE, 0xBA,
	0xE8, 0x77, 0xE9, 0x36, 0x2F, 0x77, 0xED, 0x0D, 0x4A, 0x28, 0xE3, 0x7E, 0x52, 0x86, 0x20, 0x8F,
	0xCE, 0x7A, 0x43, 0x0D, 0xFB, 0xF7, 0xAA, 0x25, 0x5F, 0xCD, 0x0C, 0x45, 0xFF, 0x7B, 0xAE, 0xC1 
};

uint8_t ecp256r1_sig[32] = 
{
	0x0F, 0xB6, 0x57, 0xEC, 0xE9, 0xC3, 0x42, 0xBD, 0xF5, 0x9F, 0x79, 0x59, 0x79, 0xD5, 0x77, 0x26,
	0xEF, 0xD5, 0xED, 0xC7, 0x72, 0x52, 0xC8, 0xE2, 0x9C, 0x40, 0x16, 0xE0, 0xA8, 0xB6, 0xFF, 0xA0,
	0x7F, 0x89, 0xB0, 0xC3, 0xAC, 0x5A, 0xFA, 0xFB, 0x89, 0x40, 0xFA, 0x6A, 0x50, 0x52, 0x0E, 0x5A,
	0x1E, 0x10, 0x7C, 0xC2, 0x6C, 0x78, 0x83, 0xE5, 0x31, 0xCC, 0x89, 0xDD, 0x4C, 0xA3, 0xA4, 0x19
};

uint8_t curve25519_gx[32] = 
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09
};

uint8_t curve25519_da[32] = 
{
	0x7D, 0x73, 0x77, 0x18, 0x3B, 0x68, 0x4A, 0x00, 0x40, 0xE7, 0x75, 0xC2, 0x4D, 0x0E, 0x5C, 0xFA, 
	0x86, 0xB0, 0x5E, 0xC1, 0xBB, 0x7B, 0x9F, 0x02, 0xA6, 0x34, 0x89, 0x29, 0xDD, 0x16, 0x42, 0xE0
};

uint8_t curve25519_qxa[32] = 
{
	0x18, 0x99, 0xF2, 0x42, 0x5B, 0x25, 0x57, 0xF9, 0xAE, 0x52, 0x70, 0xD9, 0x09, 0x13, 0xEB, 0x6A, 
	0x90, 0x0E, 0x84, 0x06, 0xBC, 0xCA, 0xC9, 0xCD, 0xA1, 0xB3, 0xA4, 0xA7, 0x3F, 0xBF, 0x01, 0xC5
};

uint8_t curve25519_shared[32] = 
{
	0x73, 0xAF, 0x14, 0x7F, 0xA6, 0x3F, 0xD1, 0x68, 0x03, 0x95, 0x74, 0x58, 0x9D, 0xB0, 0xF4, 0x15, 
	0xB1, 0x19, 0x62, 0xBD, 0xD7, 0x87, 0x7B, 0xF7, 0xBC, 0x7C, 0x04, 0x3B, 0x05, 0x5C, 0x7C, 0x3E
};

uint8_t prf_secret_shax[48] = 
{
	0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
	0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
	0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12
};

uint8_t prf_seed_shax[32] = 
{
	0x50, 0x52, 0x45, 0x20, 0x4D, 0x41, 0x53, 0x54, 0x45, 0x52, 0x20, 0x53, 0x45, 0x43, 0x52, 0x45,
	0x54, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34
};

uint8_t prf_keyblock_sha256[64] = 
{
	0x87, 0x63, 0xF3, 0x7B, 0x1E, 0x94, 0x2E, 0x7E, 0x03, 0xF1, 0xA7, 0x08, 0xDE, 0xBB, 0x70, 0xB3,
	0x51, 0x81, 0xAF, 0xAF, 0x95, 0x22, 0x68, 0x04, 0xBB, 0x6C, 0xA7, 0xA9, 0x55, 0x6D, 0xD5, 0x71,
	0x51, 0x39, 0xD6, 0xE4, 0xE4, 0x2B, 0xA6, 0x7F, 0xA9, 0x01, 0x22, 0x9E, 0x6B, 0xE5, 0xDC, 0xE9,
	0x6B, 0x01, 0x24, 0x1B, 0x62, 0x0B, 0x2E, 0xD8, 0xB2, 0x47, 0xC3, 0x3B, 0xD8, 0xA1, 0xAB, 0x4C
};

uint8_t prf_keyblock_sha384[64] = 
{
	0xAE, 0x07, 0x06, 0x87, 0xC5, 0x93, 0x4F, 0x55, 0xEB, 0x00, 0x1C, 0xE5, 0x19, 0x05, 0x3E, 0x8E,
	0x61, 0x3C, 0xF8, 0x7E, 0x72, 0x11, 0x1B, 0xC8, 0x0E, 0x3E, 0x56, 0x89, 0xB2, 0x89, 0x73, 0x03,
	0x2C, 0xFD, 0xD1, 0x8E, 0x6E, 0x83, 0x18, 0x14, 0xD9, 0xE7, 0x1D, 0x6A, 0xF2, 0x3C, 0x57, 0x48,
	0xE8, 0x06, 0x8B, 0xD3, 0xC5, 0x41, 0x56, 0x0C, 0x28, 0x51, 0x12, 0xB5, 0x3C, 0xD5, 0x24, 0xCA
};

#endif
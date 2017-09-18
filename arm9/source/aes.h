
#pragma once

#include <stdint.h>

#define RK_LEN 44 //round key length

#define AES_BLOCK_SIZE 16

void aes_gen_tables(void);

void aes_set_key_enc_128(uint32_t rk[RK_LEN], const unsigned char *key);

void aes_encrypt_128(const uint32_t rk[RK_LEN], const unsigned char input[16], unsigned char output[16]);


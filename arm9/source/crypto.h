#pragma once

#include "common.h"

#define AES_BLOCK_SIZE 16

typedef enum {
	ENCRYPT,
	DECRYPT
} crypt_mode_t;

typedef enum {
	NAND,
	NAND_3DS,
	ES
} key_mode_t;

void dsi_sha1(void *digest, const void *data, unsigned len);

void dsi_crypt_init(const u8 *console_id_be, const u8 *emmc_cid, int is3DS);

void dsi_nand_crypt_1(u8 *out, const u8* in, u32 offset);

void dsi_nand_crypt(u8 *out, const u8* in, u32 offset, unsigned count);

int dsi_es_block_crypt(u8 *buf, unsigned buf_len, crypt_mode_t mode);

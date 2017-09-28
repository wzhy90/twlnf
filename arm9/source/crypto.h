#pragma once

#include "common.h"

#define AES_BLOCK_SIZE 16

void dsi_nand_crypt_init(const u8 *console_id, const u8 *emmc_cid, int is3DS);

void dsi_nand_crypt_1(u8 *out, const u8* in, u32 offset);

void dsi_nand_crypt(u8 *out, const u8* in, u32 offset, unsigned count);

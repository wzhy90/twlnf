#pragma once

#include "common.h"

void dsi_nand_crypt_init(const u32 *console_id, const u8 *emmc_cid);

void dsi_nand_crypt(u32 *out, const u32* in, u32 offset);

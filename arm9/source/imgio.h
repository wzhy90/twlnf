#pragma once

#include <nds.h>
#include <nds/disc_io.h>

void imgio_set_fat_sig_fix(u32 offset);

bool imgio_read_raw_sectors(sec_t sector, sec_t numSectors, void *buffer);

extern const DISC_INTERFACE io_nand_img;

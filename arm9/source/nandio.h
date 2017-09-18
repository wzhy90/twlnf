#pragma once

#include <nds.h>
#include <nds/disc_io.h>

void nandio_setup_partition(sec_t offset, sec_t length);

extern const DISC_INTERFACE io_dsi_nand;

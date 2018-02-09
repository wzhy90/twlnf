
#include <nds.h>
#include <nds/disc_io.h>
#include <malloc.h>
#include <stdio.h>
#include "crypto.h"
#include "utils.h"
#include "../term256/term256ext.h"

#define SECTOR_SIZE 512
#define CRYPT_BUF_LEN 64

extern const char nand_img_name[];

static u8* crypt_buf = 0;
FILE *f = 0;

static u32 fat_sig_fix_offset = 0;

void imgio_set_fat_sig_fix(u32 offset) {
	fat_sig_fix_offset = offset;
}

// provide a similar interface to nand_ReadSectors for imgio
bool imgio_read_raw_sectors(sec_t sector, sec_t numSectors, void *buffer) {
	if (fseek(f, sector * SECTOR_SIZE, SEEK_SET) != 0) {
		prt("IMGIO: seek fail\n");
		return false;
	}
	if (fread(buffer, SECTOR_SIZE, numSectors, f) != numSectors) {
		prt("IMGIO: read fail\n");
		return false;
	}
	return true;
}

bool imgio_startup() {
	if (crypt_buf == 0) {
		crypt_buf = (u8*)memalign(32, SECTOR_SIZE * CRYPT_BUF_LEN);
		if (crypt_buf == 0) {
			prt("imgio: failed to alloc buffer\n");
		}
	}
	if (f == 0) {
		f = fopen(nand_img_name, "r+");
		if (f == 0) {
			prt("imgio: failed to open image\n");
		}
	}
	return crypt_buf != 0 && f != 0;
}

bool imgio_is_inserted() {
	return true;
}

bool dumped = false;

// len is guaranteed <= CRYPT_BUF_LEN
static bool read_sectors(sec_t start, sec_t len, void *buffer) {
	if (fseek(f, start * SECTOR_SIZE, SEEK_SET) != 0) {
		prt("IMGIO: seek fail\n");
		return false;
	}
	activity(COLOR_BRIGHT_GREEN);
	if (fread(crypt_buf, SECTOR_SIZE, len, f) == len) {
		activity(COLOR_GREEN);
		dsi_nand_crypt(buffer, crypt_buf, start * SECTOR_SIZE / AES_BLOCK_SIZE, len * SECTOR_SIZE / AES_BLOCK_SIZE);
		if (fat_sig_fix_offset &&
			start == fat_sig_fix_offset
			&& ((u8*)buffer)[0x36] == 0
			&& ((u8*)buffer)[0x37] == 0
			&& ((u8*)buffer)[0x38] == 0)
		{
			((u8*)buffer)[0x36] = 'F';
			((u8*)buffer)[0x37] = 'A';
			((u8*)buffer)[0x38] = 'T';
		}
		activity(-1);
		return true;
	} else {
		prt("IMGIO: read fail\n");
		activity(-1);
		return false;
	}
}

bool imgio_read_sectors(sec_t offset, sec_t len, void *buffer) {
	// iprintf("R: %u(0x%08x), %u\n", (unsigned)offset, (unsigned)offset, (unsigned)len);
	while (len >= CRYPT_BUF_LEN) {
		if (!read_sectors(offset, CRYPT_BUF_LEN, buffer)) {
			return false;
		}
		offset += CRYPT_BUF_LEN;
		len -= CRYPT_BUF_LEN;
		buffer = ((u8*)buffer) + SECTOR_SIZE * CRYPT_BUF_LEN;
	}
	if (len > 0) {
		return read_sectors(offset, len, buffer);
	} else {
		return true;
	}
}

static bool write_sectors(sec_t start, sec_t len, const void *buffer) {
	activity(COLOR_RED);
	dsi_nand_crypt(crypt_buf, buffer, start * SECTOR_SIZE / AES_BLOCK_SIZE, len * SECTOR_SIZE / AES_BLOCK_SIZE);
	if (fseek(f, start * SECTOR_SIZE, SEEK_SET) != 0) {
		prt("IMGIO: seek fail\n");
		activity(-1);
		return false;
	}
	activity(COLOR_BRIGHT_RED);
	if (fwrite(crypt_buf, SECTOR_SIZE, len, f) == len) {
		activity(-1);
		return true;
	} else {
		prt("IMGIO: write fail\n");
		activity(-1);
		return false;
	}
}

bool imgio_write_sectors(sec_t offset, sec_t len, const void *buffer) {
	// iprintf("W: %u(0x%08x), %u\n", (unsigned)offset, (unsigned)offset, (unsigned)len);
	while (len >= CRYPT_BUF_LEN) {
		if (!write_sectors(offset, CRYPT_BUF_LEN, buffer)) {
			return false;
		}
		offset += CRYPT_BUF_LEN;
		len -= CRYPT_BUF_LEN;
		buffer = ((u8*)buffer) + SECTOR_SIZE * CRYPT_BUF_LEN;
	}
	if (len > 0) {
		return write_sectors(offset, len, buffer);
	} else {
		return true;
	}
}

bool imgio_clear_status() {
	return true;
}

bool imgio_shutdown() {
	free(crypt_buf);
	crypt_buf = 0;
	fclose(f);
	f = 0;
	return true;
}

const DISC_INTERFACE io_nand_img = {
	('I' << 24) | ('M' << 16) | ('G' << 8) | 'C',
	FEATURE_MEDIUM_CANREAD | FEATURE_MEDIUM_CANWRITE,
	imgio_startup,
	imgio_is_inserted,
	imgio_read_sectors,
	imgio_write_sectors,
	imgio_clear_status,
	imgio_shutdown
};

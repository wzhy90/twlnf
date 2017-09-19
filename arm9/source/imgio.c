
#include <nds.h>
#include <nds/disc_io.h>
#include <malloc.h>
#include <stdio.h>
#include "aes.h"
#include "crypto.h"
#include "utils.h"

#define SECTOR_SIZE 512
#define CRYPT_BUF_LEN 64

extern const char nand_img_name[];

static u8* crypt_buf = 0;
FILE *f = 0;

bool imgio_startup() {
	if (crypt_buf == 0) {
		crypt_buf = (u8*)memalign(32, SECTOR_SIZE * CRYPT_BUF_LEN);
		if (crypt_buf == 0) {
			iprintf("imgio: failed to alloc buffer\n");
		}
	}
	if (f == 0) {
		f = fopen(nand_img_name, "r");
		if (f == 0) {
			iprintf("imgio: failed to open image\n");
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
		iprintf("IMGIO: seek fail\n");
		return false;
	}
	if (fread(crypt_buf, SECTOR_SIZE, len, f) == len) {
		dsi_nand_crypt(buffer, crypt_buf, start * SECTOR_SIZE / AES_BLOCK_SIZE, len * SECTOR_SIZE / AES_BLOCK_SIZE);
		if (start == 0x877
			&& ((u8*)buffer)[0x36] == 0
			&& ((u8*)buffer)[0x37] == 0
			&& ((u8*)buffer)[0x38] == 0){
			iprintf("IMGIO: SPECIAL FIX :P\n");
			((u8*)buffer)[0x36] = 'F';
			((u8*)buffer)[0x37] = 'A';
			((u8*)buffer)[0x38] = 'T';
		}
		return true;
	} else {
		iprintf("IMGIO: read fail\n");
		return false;
	}
}

bool imgio_read_sectors(sec_t offset, sec_t len, void *buffer) {
	iprintf("R: %u(0x%08x), %u\n", (unsigned)offset, (unsigned)offset, (unsigned)len);
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

bool imgio_write_sectors(sec_t offset, sec_t len, const void *buffer) {
	return false;
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
	FEATURE_MEDIUM_CANREAD,
	imgio_startup,
	imgio_is_inserted,
	imgio_read_sectors,
	imgio_write_sectors,
	imgio_clear_status,
	imgio_shutdown
};

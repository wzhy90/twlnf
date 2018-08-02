
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <malloc.h>
#include <nds.h>
#include <fat.h>
#include "../mbedtls/aes.h"
#include "../term256/term256ext.h"
#include "utils.h"
#include "crypto.h"
#include "sector0.h"
#include "nandio.h"
#include "imgio.h"

extern const char nand_vol_name[];
extern swiSHA1context_t sha1ctx;

const char nand_img_name[] = "nand.bin";

int is3DS;

bool (*read_raw_sectors)(sec_t, sec_t, void*) = 0;

static u32 sector_buf32[SECTOR_SIZE/sizeof(u32)];
static u8 *sector_buf = (u8*)sector_buf32;

static ssize_t nand_size;

static u32 emmc_cid32[4];
static u8 *emmc_cid = (u8*)emmc_cid32;
static u32 console_id32[2];
static u8 *console_id = (u8*)console_id32;

typedef struct {
	char footer_id[16];
	u8 emmc_cid[16];
	u8 console_id[8];
	u8 reserved[24];
} nocash_footer_t;

static_assert(sizeof(nocash_footer_t) == 0x40, "no$gba footer should be 40h bytes");

// BEWARE, this doesn't work in place
void reverse8(u8 *o, const u8 *i) {
	o[0] = i[7];
	o[1] = i[6];
	o[2] = i[5];
	o[3] = i[4];
	o[4] = i[3];
	o[5] = i[2];
	o[6] = i[1];
	o[7] = i[0];
}

int get_ids() {
	if (!isDSiMode()) {
		prt("not running in DSi mode\n");
		return -2;
	}

	fifoSendValue32(FIFO_USER_01, 1);
	while (!fifoCheckValue32(FIFO_USER_01)) swiIntrWait(1, IRQ_FIFO_NOT_EMPTY);
	int ret = fifoGetValue32(FIFO_USER_01);
	if (ret) {
		iprtf("sdmmc_nand_init() returned %d\n", ret);
		return -3;
	}

	nand_size = nand_GetSize();
	if (nand_size == 0) {
		prt("can't access eMMC\n");
		return -3;
	}
	iprtf("eMMC: %u sectors, %s MB\n", nand_size, to_mebi(nand_size * SECTOR_SIZE));

	fifoSendValue32(FIFO_USER_01, 4);
	while (fifoCheckDatamsgLength(FIFO_USER_01) < 16) swiIntrWait(1, IRQ_FIFO_NOT_EMPTY);
	fifoGetDatamsg(FIFO_USER_01, 16, (u8*)emmc_cid);
	prt("eMMC CID: ");
	print_bytes(emmc_cid, 16);
	prt("\n");

	char *p_console_id_file = 0;
	size_t console_id_file_size;
	int console_id_from_file = 0;
	if (load_file((void**)&p_console_id_file, &console_id_file_size, "console_id.txt", 0, 0) == 0) {
		if (console_id_file_size >= 16 && hex2bytes(console_id, 8, p_console_id_file) == 0) {
			console_id_from_file = 1;
		}
		free(p_console_id_file);
	}
	if (!console_id_from_file) {
		fifoSendValue32(FIFO_USER_01, 5);
		while (fifoCheckDatamsgLength(FIFO_USER_01) < 8) swiIntrWait(1, IRQ_FIFO_NOT_EMPTY);
		fifoGetDatamsg(FIFO_USER_01, 8, console_id);
	}
	iprtf("Console ID (from %s): ", console_id_from_file ? "file" : "RAM");
	print_bytes(console_id, 8);
	prt("\n");
	return 0;
}

int test_sector0(int *p_is3DS) {
	int is3DS = parse_ncsd(sector_buf, 0) == 0;
	// iprintf("sector 0 is %s\n", is3DS ? "3DS" : "DSi");
	dsi_crypt_init(console_id, emmc_cid, is3DS);
	dsi_nand_crypt(sector_buf, sector_buf, 0, SECTOR_SIZE / AES_BLOCK_SIZE);
	if (p_is3DS) {
		*p_is3DS = is3DS;
	}
	return parse_mbr(sector_buf, is3DS, 0);
}

int test_ids_against_nand(int *p_is3DS) {
	nand_ReadSectors(0, 1, sector_buf);
	return test_sector0(p_is3DS);
}

int mount(int direct) {
	mbr_t *mbr = (mbr_t*)sector_buf;
	imgio_set_fat_sig_fix(is3DS ? 0 : mbr->partitions[0].offset);
	read_raw_sectors = imgio_read_raw_sectors;
	return 0;
}

// to prevent possible alloc failure for critical restore
#define SECTORS_PER_LOOP 128
#define DUMP_BUF_SIZE (SECTOR_SIZE * SECTORS_PER_LOOP)
u32 dump_buf[DUMP_BUF_SIZE / sizeof(u32)];

void aes_test(int loops, const char * s_console_id, const char * s_emmc_cid) {
	hex2bytes(console_id, 8, s_console_id);
	hex2bytes(emmc_cid, 16, s_emmc_cid);
	dsi_crypt_init(console_id, emmc_cid, 0);

	cpuStartTiming(0);
	for (int i = 0; i < loops; ++i) {
		dsi_nand_crypt((u8*)dump_buf, (u8*)dump_buf,
			i * (DUMP_BUF_SIZE / AES_BLOCK_SIZE), DUMP_BUF_SIZE / AES_BLOCK_SIZE);
	}
	u32 td = timerTicks2usec(cpuEndTiming());

	prtf("%" PRIu32 " us %u KB\n%.2f KB/s\n", td, (DUMP_BUF_SIZE * loops) >> 10,
		1000.0f * DUMP_BUF_SIZE * loops / td);
}


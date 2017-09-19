#include <nds.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fat.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <dirent.h>
#include <sys/statvfs.h>
#include "aes.h"
#include "utils.h"
#include "crypto.h"
#include "sector0.h"
#include "nandio.h"
#include "imgio.h"

#define IMG_MODE 1

#define BUF_SIZE	(1*1024*1024)

u8 *buffer;

PrintConsole topScreen;
PrintConsole bottomScreen;

u8 nandcid[16];
u8 consoleid[8];

swiSHA1context_t sha1ctx;

char dirname[15] = "FW";

const u8 mbr_1f0_verify[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x55, 0xaa };

#if IMG_MODE
const char nand_img_name[] = "nand.bin";
#endif

const char nand_vol_name[] = "NAND";
const char nand_root[] = "NAND:/";

void exit_with_prompt(int exit_code) {
	iprintf("press A to exit...");
	while (1) {
		swiWaitForVBlank();
		scanKeys();
		if (keysDown() & KEY_A) break;
	}
	exit(exit_code);
}

size_t df(int verbose) {
	// it's amazing libfat even got this to work
	struct statvfs s;
	statvfs(nand_root, &s);
	size_t free = s.f_bsize * s.f_bfree;
	if (verbose) {
		iprintf("%s", toMebi(free));
		iprintf("/%s MB (free/total)\n", toMebi(s.f_bsize * s.f_blocks));
	}
	return free;
}

//---------------------------------------------------------------------------------
int main() {
	//---------------------------------------------------------------------------------
	defaultExceptionHandler();

	videoSetMode(MODE_0_2D);
	videoSetModeSub(MODE_0_2D);

	vramSetBankA(VRAM_A_MAIN_BG);
	vramSetBankC(VRAM_C_SUB_BG);

	consoleInit(&topScreen, 3, BgType_Text4bpp, BgSize_T_256x256, 31, 0, true, true);
	consoleInit(&bottomScreen, 3, BgType_Text4bpp, BgSize_T_256x256, 31, 0, false, true);

	consoleSelect(&bottomScreen);

	iprintf("FAT init...");

	if (!fatInitDefault()) {
		iprintf("\rFAT init failed!\n");
		exit_with_prompt(-1);
	} else {
		iprintf("\rFAT init succeed\n");
	}

	buffer = (u8 *)memalign(32, BUF_SIZE);

	if (!isDSiMode()) {
		iprintf("not running in DSi mode\n");
		exit_with_prompt(-2);
	}

	ssize_t nandSize = nand_GetSize();
	if (nandSize == 0) {
		iprintf("can't access NAND\n");
		exit_with_prompt(-3);
	}

	iprintf("NAND: %d sectors, %s MB\n", nandSize, toMebi(nandSize * 512));

	iprintf("NAND CID:\n");
#if IMG_MODE
	char *pCIDFile = 0;
	size_t CIDFileSize;
	bool CIDFromFile = false;
	if (loadFromFile((void**)&pCIDFile, &CIDFileSize, "cid.txt", false, 0) == 0) {
		if (CIDFileSize >= 32 && hexToBytes(nandcid, 16, pCIDFile) == 0) {
			CIDFromFile = true;
		}
		free(pCIDFile);
	}
	if (!CIDFromFile) {
		iprintf("cid.txt missing/invalid\n");
		exit_with_prompt(0);
	}
#else
	fifoSendValue32(FIFO_USER_01, 4);
	while (fifoCheckDatamsgLength(FIFO_USER_01) < 16) swiIntrWait(1, IRQ_FIFO_NOT_EMPTY);
	fifoGetDatamsg(FIFO_USER_01, 16, (u8*)nandcid);
#endif
	printBytes(nandcid, 16);

	char *pConsoleIDFile = 0;
	size_t ConsoleIDFileSize;
	bool consoleIDFromFile = false;
	if (loadFromFile((void**)&pConsoleIDFile, &ConsoleIDFileSize, "console_id.txt", false, 0) == 0) {
		if (ConsoleIDFileSize >= 16 && hexToBytes(consoleid, 8, pConsoleIDFile) == 0) {
			consoleIDFromFile = true;
		}
		free(pConsoleIDFile);
	}
	if (!consoleIDFromFile) {
#if IMG_MODE
		iprintf("console_id.txt missing/invalid\n");
		exit_with_prompt(0);
#else
		fifoSendValue32(FIFO_USER_01, 5);
		while (fifoCheckDatamsgLength(FIFO_USER_01) < 8) swiIntrWait(1, IRQ_FIFO_NOT_EMPTY);
		fifoGetDatamsg(FIFO_USER_01, 8, consoleid);
#endif
	}
	iprintf("Console ID (from %s):\n", consoleIDFromFile ? "file" : "RAM");
	printBytes(consoleid, 8);
	iprintf("\n");

	// check NCSD header
#if IMG_MODE
	FILE *f = fopen(nand_img_name, "r");
	if (f == 0) {
		iprintf("can't open %s\n", nand_img_name);
		exit_with_prompt(0);
	}
	size_t read = fread(buffer, 1, SECTOR_SIZE, f);
	if (read != SECTOR_SIZE) {
		iprintf("read = %u, expecting %u\n", (unsigned)read, SECTOR_SIZE);
		exit_with_prompt(0);
	}
	fclose(f);
#else
	nand_ReadSectors(0, 1, buffer);
#endif
	int is3DS = parse_ncsd(buffer, 0);
	iprintf("%s mode\n", is3DS ? "3DS" : "DSi");

	dsi_nand_crypt_init(consoleid, nandcid, is3DS);

	// check MBR
	dsi_nand_crypt(buffer, buffer, 0, SECTOR_SIZE / AES_BLOCK_SIZE);
	int mbr_ok = parse_mbr(buffer, is3DS, 0);
	if (mbr_ok != 1) {
		iprintf("most likely Console ID is wrong\n");
		exit_with_prompt(-4);
	} else {
		iprintf("MBR OK\n");
	}

	// finally mount NAND
#if IMG_MODE
	mbr_t *mbr = (mbr_t*)buffer;
	if (!fatMount(nand_vol_name, &io_nand_img, mbr->partitions[0].offset, 4, 64)) {
#else
	if (!fatMountSimple(nand_vol_name, &io_dsi_nand)) {
#endif
		iprintf("failed to mount NAND\n");
		exit_with_prompt(-5);
	} else {
		iprintf("NAND mounted\n");
	}

	/* // the volume label is all white space?
	char vol_label[32];
	fatGetVolumeLabel(nand_vol_name, vol_label);
	iprintf("Label: \"%s\"\n", vol_label);
	*/
	df(1);

	DIR *d = opendir(nand_root);
	if (d == 0) {
		iprintf("failed to open dir\n");
		exit_with_prompt(-6);
	}
	consoleSelect(&topScreen);
	struct dirent *e;
	while ((e = readdir(d)) != 0) {
		iprintf("%s\n", e->d_name);
	}
	closedir(d);
	consoleSelect(&bottomScreen);
	
	exit_with_prompt(0);
}

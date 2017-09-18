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
#include "aes.h"
#include "utils.h"
#include "crypto.h"
#include "sector0.h"
#include "nandio.h"

#define BUF_SIZE	(1*1024*1024)

u8 *buffer;

PrintConsole topScreen;
PrintConsole bottomScreen;

u8 nandcid[16];
u8 consoleid[8];

swiSHA1context_t sha1ctx;

char dirname[15] = "FW";

const u8 mbr_1f0_verify[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x55, 0xaa };

const char nand_vol_name[] = "NAND";

void exit_with_prompt(int exit_code) {
	iprintf("press A to exit...");
	while (1) {
		swiWaitForVBlank();
		scanKeys();
		if (keysDown() & KEY_A) break;
	}
	exit(exit_code);
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

	readFirmware(0, buffer, 512);

	iprintf("MAC: ");
	for (int i = 0; i < 6; i++) {
		iprintf("%02X", buffer[0x36 + i]);
		sprintf(&dirname[2 + (2 * i)], "%02X", buffer[0x36 + i]);
		iprintf(i < 5 ? ":" : "\n");
	}
	dirname[14] = 0;
	mkdir(dirname, 0777);
	chdir(dirname);

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
	fifoSendValue32(FIFO_USER_01, 4);
	while (fifoCheckDatamsgLength(FIFO_USER_01) < 16) swiIntrWait(1, IRQ_FIFO_NOT_EMPTY);
	fifoGetDatamsg(FIFO_USER_01, 16, (u8*)nandcid);
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
		fifoSendValue32(FIFO_USER_01, 5);
		while (fifoCheckDatamsgLength(FIFO_USER_01) < 8) swiIntrWait(1, IRQ_FIFO_NOT_EMPTY);
		fifoGetDatamsg(FIFO_USER_01, 8, consoleid);
	}
	iprintf("Console ID (from %s):\n", consoleIDFromFile ? "file" : "RAM");
	printBytes(consoleid, 8);
	iprintf("\n");

	// check NCSD header
	nand_ReadSectors(0, 1, buffer);
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
	if (!fatMountSimple(nand_vol_name, &io_dsi_nand)) {
		iprintf("failed to mount NAND\n");
		exit_with_prompt(-5);
	} else {
		iprintf("NAND mounted\n");
	}

	char vol_label[32];
	fatGetVolumeLabel(nand_vol_name, vol_label);
	iprintf("Label: \"%s\"\n", vol_label);

	DIR *d = opendir("NAND:/");
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

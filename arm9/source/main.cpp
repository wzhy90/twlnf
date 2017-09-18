#include <nds.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fat.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include "utils.h"
#include "crypto.h"

#define MAX_SIZE	(1*1024*1024)

int menuTop = 8, statusTop = 15;

PrintConsole topScreen;
PrintConsole bottomScreen;

u8 nandcid[16];
u8 consoleid[8];

swiSHA1context_t sha1ctx;

//---------------------------------------------------------------------------------
int readJEDEC() {
//---------------------------------------------------------------------------------

	fifoSendValue32(FIFO_USER_01, 1);

	fifoWaitValue32(FIFO_USER_01);

	return  fifoGetValue32(FIFO_USER_01);
}

struct menuItem {
	const char* name;
	fp function;
};

u8 *firmware_buffer;
size_t userSettingsOffset, fwSize, wifiOffset, wifiSize;

//---------------------------------------------------------------------------------
void clearStatus() {
//---------------------------------------------------------------------------------
	iprintf("\x1b[%d;0H\x1b[J\x1b[15;0H",statusTop);
}

//---------------------------------------------------------------------------------
void dummy() {
//---------------------------------------------------------------------------------
	clearStatus();
	iprintf("\x1b[%d;6HNOT IMPLEMENTED!",statusTop+3);
}

char dirname[15] = "FW";
char serial[13];

//---------------------------------------------------------------------------------
void backupFirmware() {
//---------------------------------------------------------------------------------

	clearStatus();

	readFirmware(0, firmware_buffer, fwSize);

	saveToFile("firmware.bin", firmware_buffer, fwSize, true);

}

const u8 arm7bios[32] = {
	0x06, 0x00, 0x00, 0xEA, 0x20, 0x0B, 0x00, 0xEA,
	0x73, 0x0B, 0x00, 0xEA, 0x1E, 0x0B, 0x00, 0xEA,
	0x1D, 0x0B, 0x00, 0xEA, 0x1C, 0x0B, 0x00, 0xEA,
	0x69, 0x0B, 0x00, 0xEA, 0x1A, 0x0B, 0x00, 0xEA
};

const u8 arm7ibios[32] = {
	0x06, 0x00, 0x00, 0xEA, 0x06, 0x00, 0x00, 0xEA,
	0x1F, 0x00, 0x00, 0xEA,	0x04, 0x00, 0x00, 0xEA,
	0x03, 0x00, 0x00, 0xEA, 0xFE, 0xFF, 0xFF, 0xEA,
	0x13, 0x00, 0x00, 0xEA, 0x00, 0x00, 0x00, 0xEA
};


//---------------------------------------------------------------------------------
void flipBIOS() {
//---------------------------------------------------------------------------------
	fifoSendValue32(FIFO_USER_01, 2);
	fifoWaitValue32(FIFO_USER_01); fifoGetValue32(FIFO_USER_01);
}

//---------------------------------------------------------------------------------
void dumpBIOS(void *buffer) {
//---------------------------------------------------------------------------------
	fifoSendValue32(FIFO_USER_01, 3);
	fifoSendValue32(FIFO_USER_01, (u32)buffer);
	fifoWaitValue32(FIFO_USER_01); fifoGetValue32(FIFO_USER_01);
}

//---------------------------------------------------------------------------------
void backupBIOS() {
//---------------------------------------------------------------------------------

	clearStatus();

	const char *arm7file, *arm9file;
	const u8 *vectors;

	size_t arm7size, arm9size;


	if (isDSiMode()) {

		int dsbios = REG_SCFG_ROM & 0x02;
		flipBIOS();

		if ((REG_SCFG_ROM & 0x02)!=dsbios) {
			dumpBIOS(firmware_buffer);
			memcpy(firmware_buffer,arm7bios,sizeof(arm7bios));
			saveToFile("bios7.bin", firmware_buffer, 16 * 1024, true);
			saveToFile("bios9.bin", (u8*)0xffff0000, 32 * 1024, true);
			flipBIOS();

		}

		arm7file = "bios7i.bin";
		arm7size = 64 * 1024;
		arm9file = "bios9i.bin";
		arm9size = 64 * 1024;
		vectors = arm7ibios;
	} else {
		arm7file = "bios7.bin";
		arm7size = 16 * 1024;
		arm9file = "bios9.bin";
		arm9size = 32 * 1024;
		vectors = arm7bios;
	}

	dumpBIOS(firmware_buffer);
	memcpy(firmware_buffer,vectors,32);
	saveToFile(arm9file, (u8*)0xffff0000, arm9size, true);
	saveToFile(arm7file, firmware_buffer, arm7size, true);

}

//---------------------------------------------------------------------------------
void backupSettings() {
//---------------------------------------------------------------------------------

	clearStatus();

	readFirmware(userSettingsOffset, firmware_buffer + userSettingsOffset, 512);

	if (saveToFile("UserSettings.bin", firmware_buffer + userSettingsOffset, 512, true) < 0) {
		iprintf("Error saving settings1!\n");
	} else {
		iprintf("User settings saved as\n\n%s/UserSettings.bin", dirname );
	}
}

//---------------------------------------------------------------------------------
void backupWifi() {
//---------------------------------------------------------------------------------

	clearStatus();

	readFirmware(wifiOffset, firmware_buffer + wifiOffset, wifiSize);

	if (saveToFile("WifiSettings.bin", firmware_buffer + wifiOffset, wifiSize, true) < 0) {
		iprintf("Error saving Wifi settings!\n");
	} else {
		iprintf("Wifi settings saved as\n\n%s/WifiSettings.bin", dirname );
	}
}

//---------------------------------------------------------------------------------
void backupNAND() {
//---------------------------------------------------------------------------------

	clearStatus();


	if (!isDSiMode()) {
		iprintf("Not a DSi!\n");
	} else {

		const char *filename = "nand.bin";
		FILE *f = fopen(filename, "wb");

		if (NULL == f) {
			iprintf("failure creating %s\n", filename);
		} else {
			iprintf("Writing %s/%s\n\n", dirname, filename);
			size_t i;
			size_t sectors = 128;
			size_t blocks = nand_GetSize() / sectors;
			sha1ctx.sha_block = 0;
			swiSHA1Init(&sha1ctx);
			for (i=0; i < blocks; i++) {
				if(!nand_ReadSectors(i * sectors,sectors,firmware_buffer)) {
					iprintf("\nError reading NAND!\n");
					break;
				}
				swiSHA1Update(&sha1ctx, firmware_buffer, 512 * sectors);
				size_t written = fwrite(firmware_buffer, 1, 512 * sectors, f);
				if(written != 512 * sectors) {
					iprintf("\nError writing to SD!\n");
					break;
				}
				iprintf("Block %d of %d\r", i+1, blocks);
			}
			fclose(f);
			saveSHA1File(filename);
		}
	}

}

bool quitting = false;

//---------------------------------------------------------------------------------
void quit() {
//---------------------------------------------------------------------------------
	quitting = true;
}

struct menuItem mainMenu[] = {
	{ "Backup Firmware", backupFirmware } ,
	{ "Dump Bios", backupBIOS } ,
	{ "Backup User Settings", backupSettings } ,
	{ "Backup Wifi Settings", backupWifi } ,
	{ "Backup DSi NAND", backupNAND},
/*
	TODO

	{ "Restore Firmware", dummy } ,
	{ "Restore User Settings", dummy } ,
	{ "Restore Wifi Settings", dummy } ,
*/	{ "Exit", quit }
};

//---------------------------------------------------------------------------------
void showMenu(menuItem menu[], int count) {
//---------------------------------------------------------------------------------
	int i;
	for (i=0; i<count; i++ ) {
		iprintf("\x1b[%d;5H%s", i + menuTop, menu[i].name);
	}
}


//---------------------------------------------------------------------------------
int main() {
//---------------------------------------------------------------------------------
	defaultExceptionHandler();

	videoSetMode(MODE_0_2D);
	videoSetModeSub(MODE_0_2D);

	vramSetBankA(VRAM_A_MAIN_BG);
	vramSetBankC(VRAM_C_SUB_BG);

	consoleInit(&topScreen, 3,BgType_Text4bpp, BgSize_T_256x256, 31, 0, true, true);
	consoleInit(&bottomScreen, 3,BgType_Text4bpp, BgSize_T_256x256, 31, 0, false, true);

	consoleSelect(&topScreen);

	iprintf("DS(i) firmware tool %s\n",VERSION);

	if (!fatInitDefault()) {
		iprintf("FAT init failed!\n");
		while(1) {
			swiWaitForVBlank();
			scanKeys();
			if(keysDown() & KEY_A) break;
		}
	} else {


		consoleSelect(&bottomScreen);
		firmware_buffer = (u8 *)memalign(32,MAX_SIZE);

		readFirmware(0, firmware_buffer, 512);

		iprintf("MAC ");
		for (int i=0; i<6; i++) {
			printf("%02X", firmware_buffer[0x36+i]);
			sprintf(&dirname[2+(2*i)],"%02X",firmware_buffer[0x36+i]);
			if (i < 5) printf(":");
		}


		dirname[14] = 0;

		mkdir(dirname, 0777);
		chdir(dirname);

		userSettingsOffset = (firmware_buffer[32] + (firmware_buffer[33] << 8)) *8;

		fwSize = userSettingsOffset + 512;

		iprintf("\n%dK flash, jedec %X\n", fwSize/1024,readJEDEC());

		wifiOffset = userSettingsOffset - 1024;
		wifiSize = 1024;

		if ( firmware_buffer[29] == 0x57 ) {
			wifiOffset -= 1536;
			wifiSize += 1536;
		}

		if (isDSiMode()) {

			ssize_t nandSize = nand_GetSize();

			if (nandSize * 512 % (1024 * 1024) == 0) {
				iprintf("NAND: %d sectors, %d MB\n", nandSize, nandSize * 512 / 1024 / 1024);
			} else {
				iprintf("NAND: %d sectors, %.2f MB\n", nandSize, nandSize * (512.0 / 1024 / 1024));
			}

			if (0 != nandSize) {
				iprintf("NAND CID (from MMC CMD):\n");
				fifoSendValue32(FIFO_USER_01, 4);
				while(fifoCheckDatamsgLength(FIFO_USER_01) < 16) swiIntrWait(1,IRQ_FIFO_NOT_EMPTY);
				fifoGetDatamsg(FIFO_USER_01,16,(u8*)nandcid);
				printBytes(nandcid, 16);
			} else {
				iprintf("NAND CID (from RAM):\n");
				u8 *ramcid = (u8*)0x02FFD7BC;
				printBytes(ramcid, 16);
			}
			char *pConsoleIDFile = 0;
			size_t ConsoleIDFileSize;
			bool consoleidFromFile = false;
			if (loadFromFile((void**)&pConsoleIDFile, &ConsoleIDFileSize, "console id.txt", false, 0) == 0){
				if (ConsoleIDFileSize >= 16 && hexToBytes(consoleid, 8, pConsoleIDFile) == 0) {
					consoleidFromFile = true;
					iprintf("Console ID (from file): ");
				}
				free(pConsoleIDFile);
			}
			if (!consoleidFromFile) {
				iprintf("Console ID (from RAM): ");
				fifoSendValue32(FIFO_USER_01, 5);
				while(fifoCheckDatamsgLength(FIFO_USER_01) < 8) swiIntrWait(1,IRQ_FIFO_NOT_EMPTY);
				fifoGetDatamsg(FIFO_USER_01,8,consoleid);
			}
			printBytes(consoleid, 8);

			// TODO: parse sector 0
		}

		iprintf("\n");

		consoleSelect(&topScreen);

		int count = sizeof(mainMenu) / sizeof(menuItem);

		showMenu(mainMenu, count);

		int selected = 0;
		quitting = false;

		while(!quitting) {
				iprintf("\x1b[%d;3H]\x1b[23C[",selected + menuTop);
				swiWaitForVBlank();
				scanKeys();
				int keys = keysDownRepeat();
				iprintf("\x1b[%d;3H \x1b[23C ",selected + menuTop);
				if ( (keys & KEY_UP)) selected--;
				if (selected < 0)	selected = count - 1;
				if ( (keys & KEY_DOWN)) selected++;
				if (selected == count)	selected = 0;
				if ( keys & KEY_A ) mainMenu[selected].function();
		}
	}


	return 0;
}

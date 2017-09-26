#include <nds.h>

//---------------------------------------------------------------------------------
void VcountHandler() {
//---------------------------------------------------------------------------------
	inputGetAndSend();
}

volatile bool exitflag = false;

//---------------------------------------------------------------------------------
void powerButtonCB() {
//---------------------------------------------------------------------------------
	exitflag = true;
}


u64 consoleid;
u32 buf32[4];

//---------------------------------------------------------------------------------
int main() {
//---------------------------------------------------------------------------------
	readUserSettings();

	irqInit();
	// Start the RTC tracking IRQ
	initClockIRQ();
	fifoInit();
	touchInit();

	SetYtrigger(80);

	installSoundFIFO();

	installSystemFIFO();

	irqSet(IRQ_VCOUNT, VcountHandler);

	irqEnable( IRQ_VBLANK | IRQ_VCOUNT);
	
	setPowerButtonCB(powerButtonCB);   

	// Keep the ARM7 mostly idle
	while (!exitflag) {

		swiIntrWait(1,IRQ_FIFO_NOT_EMPTY);

		if (fifoCheckValue32(FIFO_USER_01)) {

			int command = fifoGetValue32(FIFO_USER_01);
			switch(command) {
				case 4:
					sdmmc_nand_cid(buf32);
					fifoSendDatamsg(FIFO_USER_01, 16, (u8*)buf32);
					break;
				case 5:
					// works on no$gba but all 0 real DSi(4swordshax) or 3DS(hbmenu cia)
					consoleid = REG_CONSOLEID;
					fifoSendDatamsg(FIFO_USER_01, 8, (u8*)&consoleid);
					break;
				case 200:
					// again works on no$gba but all 0 on real DSi or 3DS
					buf32[0] = ((vu32*)(&REG_CONSOLEID))[0];
					buf32[1] = ((vu32*)(&REG_CONSOLEID))[1];
					fifoSendDatamsg(FIFO_USER_01, 8, (u8*)buf32);
					break;
				case 201:
					REG_AES_CNT = AES_CNT_ENABLE | AES_CNT_MODE(2);
					buf32[0] = REG_AES_CNT;
					fifoSendDatamsg(FIFO_USER_01, 4, (u8*)buf32);
					break;
			}

		}

		if ( 0 == (REG_KEYINPUT & (KEY_SELECT | KEY_START | KEY_L | KEY_R))) {
			exitflag = true;
		}
	}
	return 0;
}

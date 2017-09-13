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

static u8 readwriteSPI(u8 data) {
	REG_SPIDATA = data;
	SerialWaitBusy();
	return REG_SPIDATA;
}

void readBios(u8 *buffer);
void readDSiBios(u8 *buffer);


//---------------------------------------------------------------------------------
u8 *getDumpAddress() {
//---------------------------------------------------------------------------------

	while(!fifoCheckValue32(FIFO_USER_01)) {
		swiIntrWait(1,IRQ_FIFO_NOT_EMPTY);
	}

	return (u8 *)fifoGetValue32(FIFO_USER_01);

}


//---------------------------------------------------------------------------------
void dumpDSiBios() {
//---------------------------------------------------------------------------------
	u8 *dumped_bios = getDumpAddress();
	readDSiBios(dumped_bios);
	fifoSendValue32(FIFO_USER_01,0);
}

//---------------------------------------------------------------------------------
void dumpBIOS() {
//---------------------------------------------------------------------------------
	u8 *dumped_bios = getDumpAddress();
	if (isDSiMode() && !(REG_SCFG_A7ROM & 0x02)) {
		readDSiBios(dumped_bios);
	} else {
		readBios(dumped_bios);
	}
	fifoSendValue32(FIFO_USER_01,0);
}


//---------------------------------------------------------------------------------
int readJEDEC() {
//---------------------------------------------------------------------------------
	// read jedec id
	int jedec = 0;
	REG_SPICNT = SPI_ENABLE | SPI_BAUD_4MHz | SPI_DEVICE_NVRAM | SPI_CONTINUOUS;
	readwriteSPI(SPI_EEPROM_RDID);
	jedec = readwriteSPI(0);
	jedec = ( jedec << 8 ) + readwriteSPI(0);
	jedec = ( jedec << 8 ) + readwriteSPI(0);
	
	REG_SPICNT = 0;

	return jedec;

}

//---------------------------------------------------------------------------------
void flipBIOS() {
//---------------------------------------------------------------------------------
	REG_SCFG_A9ROM ^= 0x02;
	REG_SCFG_A7ROM ^= 0x02;
	fifoSendValue32(FIFO_USER_01,0);
}

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

			u64 consoleid;
			u32 nand_cid[4];

			switch(command) {
				case 1:
					fifoSendValue32(FIFO_USER_01,readJEDEC());
					break;
				case 2:
					flipBIOS();
					break;
				case 3:
					dumpBIOS();
					break;
				case 4:
					sdmmc_nand_cid(nand_cid);
					fifoSendDatamsg(FIFO_USER_01, 16, (u8*)nand_cid);
					break;
				case 5:
					consoleid = REG_CONSOLEID;
					fifoSendDatamsg(FIFO_USER_01, 8, (u8*)&consoleid);
					break;
			}

		}

		if ( 0 == (REG_KEYINPUT & (KEY_SELECT | KEY_START | KEY_L | KEY_R))) {
			exitflag = true;
		}
	}
	return 0;
}

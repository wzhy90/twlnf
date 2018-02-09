
#include <nds.h>
#include <nds/disc_io.h>
#include <stdio.h>
#include <assert.h>
#include "../term256/term256ext.h"
#include "stage2.h"

#define SECTOR_SIZE 512
#define BUF_LEN 64

extern bool (*read_raw_sectors)(sec_t, sec_t, void*);

extern int is3DS;

// http://problemkaputt.de/gbatek.htm#dsisdmmcinternalnandlayout

typedef struct {
	u32 offset;
	u32 size;
	u32 ram_address;
	u32 size_r;
} DSi_Stage2_Boot_Code_Descriptor;

static_assert(sizeof(DSi_Stage2_Boot_Code_Descriptor) == sizeof(u32) * 4,
	"DSi_Stage2_Boot_Code_Descryptor invalid size");

typedef struct {
	u8 zero[0x20];
	DSi_Stage2_Boot_Code_Descriptor s2bcd[2];
} DSi_Stage2_Boot_Info_Block;

static_assert(sizeof(DSi_Stage2_Boot_Info_Block) == 0x20 + sizeof(DSi_Stage2_Boot_Code_Descriptor) * 2,
	"DSi_Stage2_Boot_Info_Block invalid size");

int dump_stage2(DSi_Stage2_Index s2idx , const char *filename) {
	if (is3DS) {
		iprtf("%s: this doesn't work on 3DS\n", __FUNCTION__);
		return -1;
	}
	iprtf("dump stage 2 boot %s code to: %s\n", s2idx == STAGE2_ARM9 ? "ARM9" : "ARM7", filename);
	u8* buf = (u8*)memalign(32, SECTOR_SIZE * BUF_LEN);
	if (buf == 0) {
		iprtf("%s: failed to alloc buffer\n", __FUNCTION__);
		return -1;
	}
	read_raw_sectors(1, 1, buf);
	DSi_Stage2_Boot_Info_Block *s2bib = (DSi_Stage2_Boot_Info_Block*)buf;
	iprtf("\toffset: 0x%lx\n", s2bib->s2bcd[s2idx].offset);
	iprtf("\tsize:   0x%lx\n", s2bib->s2bcd[s2idx].size);

	return 0;
}

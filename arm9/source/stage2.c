
#include <nds.h>
#include <nds/disc_io.h>
#include <stdio.h>
#include <assert.h>
#include "../term256/term256ext.h"
#include "crypto.h"
#include "utils.h"
#include "stage2.h"

#define SECTOR_SIZE 512

extern bool (*read_raw_sectors)(sec_t, sec_t, void*);

extern int is3DS;

extern swiSHA1context_t sha1ctx;

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
	iprtf("dump stage2 %s to: %s\n", s2idx == STAGE2_ARM9 ? "ARM9" : "ARM7", filename);
	/*
	FILE *f = fopen(filename, "w");
	if (f == 0) {
		iprtf("failed to open %s for writing\n", filename);
		return -1;
	}
	*/
	u8* buf = (u8*)memalign(32, SECTOR_SIZE);
	if (buf == 0) {
		prt("failed to alloc buffer\n");
		return -1;
	}
	read_raw_sectors(1, 1, buf);
	DSi_Stage2_Boot_Info_Block *s2bib = (DSi_Stage2_Boot_Info_Block*)buf;
	u32 offset = s2bib->s2bcd[s2idx].offset;
	u32 size_r = s2bib->s2bcd[s2idx].size_r;
	iprtf("\toffset: 0x%lx\n", offset);
	iprtf("\tsize_r: 0x%lx(%ld)\n", size_r, size_r);

	assert(size_r % SECTOR_SIZE == 0);
	dsi_boot2_crypt_set_ctr(size_r);

	swiSHA1context_t sha1ctx_raw;
	sha1ctx_raw.sha_block = 0;
	swiSHA1Init(&sha1ctx_raw);

	sha1ctx.sha_block = 0;
	swiSHA1Init(&sha1ctx);

	for (unsigned i = 0; i < size_r / SECTOR_SIZE; ++i) {
		if (!read_raw_sectors(offset / SECTOR_SIZE + i, 1, buf)) {
			iprtf("\nerror reading sector %ld\n", offset / SECTOR_SIZE + i);
		}
		swiSHA1Update(&sha1ctx_raw, buf, SECTOR_SIZE);
		dsi_boot2_crypt(buf, buf, SECTOR_SIZE / AES_BLOCK_SIZE);
		swiSHA1Update(&sha1ctx, buf, SECTOR_SIZE);
		// fwrite(buf, SECTOR_SIZE, 1, f);
		iprtf("\r%d/%ld", i + 1, size_r / SECTOR_SIZE);
	}
	prt("\ndone\n");

	// fclose(f);
	// save_sha1_file(filename);
	u32 sha1[5];
	swiSHA1Final(sha1, &sha1ctx_raw);
	print_bytes(sha1, 20);
	prt("\n");
	swiSHA1Final(sha1, &sha1ctx);
	print_bytes(sha1, 20);
	prt("\n");

	free(buf);
	return 0;
}

#pragma once

typedef enum {
	STAGE2_ARM9 = 0,
	STAGE2_ARM7 = 1
} DSi_Stage2_Index;

int dump_stage2(DSi_Stage2_Index s2idx , const char *filename);

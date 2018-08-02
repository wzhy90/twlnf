#pragma once

int get_ids();

int test_sector0(int *p_is3DS);

int test_ids_against_nand();

int mount(int direct);

void aes_test(int loops, const char * s_console_id, const char * s_emmc_cid);

#pragma once

int get_ids();

int test_sector0(int *p_is3DS);

int test_ids_against_nand();

int test_image_against_nand();

int test_image_against_footer();

int mount(int direct);

int backup();

int restore();

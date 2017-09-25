#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <nds.h>
#include <fat.h>
#include "utils.h"
#include "walk.h"
#include "nand.h"
#include "scripting.h"
#include "term256ext.h"

#define SHA1_LEN 20

#define RESERVE_FREE (5 * 1024 * 1024)

term_t t0;
term_t t1;

extern const char nand_img_name[];

unsigned executions = 0;

const char nand_vol_name[] = "NAND";
const char nand_root[] = "NAND:/";

#define Cls "\x1b[2J"
#define Rst "\x1b[0m"
#define BlkOnWht "\x1b[30;47m"
#define CyanOnBlk "\x1b[32;1;40m"
#define BlkOnRed "\x1b[31;1;7;30m"

typedef struct {
	const char *name;
	size_t size;
}file_list_item_t;

#define FILE_LIST_LEN 0x100

const char list_dir[] = "scripts/";
const char footer[] = "(A)select (B)quit (START)menu";
file_list_item_t file_list[FILE_LIST_LEN];
unsigned file_list_len;
unsigned view_pos;
unsigned cur_pos;

#define VIEW_ROWS (TERM_ROWS - 2)

void file_list_add(const char *name, size_t size, void *_) {
	if (file_list_len == FILE_LIST_LEN) {
		return;
	}
	if (size == INVALID_SIZE) {
		// filter out directory
		return;
	}
	unsigned len_name = strlen(name);
	if (len_name < 5) {
		// shortest valid name would be like "1.nfs"
		return;
	}
	// abbreviation for NAND File Script
	if (strcmp(".nfs", name + len_name - 4)){
		return;
	}
	char *name_copy = malloc(len_name + 1);
	strcpy(name_copy, name);
	file_list[file_list_len].name = name_copy;
	file_list[file_list_len].size = size;
	++file_list_len;
}

char size_str_buf[TERM_COLS];
char name_str_buf[TERM_COLS];
const char whitespace[] = "                                          ";
static_assert(sizeof(whitespace) == TERM_COLS + 1, "the white space buf is not long enough");

void draw_file_list() {
	select_term(&t1);
	int len_size = sniprintf(size_str_buf, TERM_COLS, "%u/%u", view_pos + cur_pos + 1, file_list_len);
	prt(Rst Cls BlkOnWht);
	// iprtf("%s%s%s" seems dumb
	prt(list_dir);
	prt(whitespace + strlen(list_dir) + len_size);
	prt(size_str_buf);
	for (unsigned i = 0; i < VIEW_ROWS; ++i) {
		if (view_pos + i < file_list_len) {
			prt(i == cur_pos ? CyanOnBlk : Rst);
			file_list_item_t *item = &file_list[view_pos + i];
			len_size = sniprintf(size_str_buf, TERM_COLS, "%u", item->size);
			// cut off the name if too long
			int len_name = strlen(item->name);
			if (len_name + 1 + len_size > TERM_COLS) {
				strncpy(name_str_buf, item->name, TERM_COLS - len_size - 5);
				strcpy(name_str_buf + TERM_COLS - len_size - 5, " ...");
				prt(name_str_buf);
				prt(" ");
				prt(size_str_buf);
			} else {
				prt(item->name);
				prt(whitespace + len_name + len_size);
				prt(size_str_buf);
			}
		}
	}
	iprtf("\x1b[%d;1H", TERM_ROWS);
	prt(BlkOnWht);
	prt(footer);
	prt(whitespace + strlen(footer));
	select_term(&t0);
}

void menu_move(int move) {
	unsigned last_pos = file_list_len < VIEW_ROWS ? file_list_len - 1 : VIEW_ROWS - 1;
	switch (move) {
	case -1:
		if (cur_pos > 0) {
			--cur_pos;
		} else if (view_pos > 0) {
			--view_pos;
		}
		break;
	case 1:
		if (cur_pos < last_pos) {
			++cur_pos;
		} else if (view_pos + VIEW_ROWS < file_list_len){
			++view_pos;
		}
		break;
	case -2:
		if (cur_pos > 0) {
			cur_pos = 0;
		} else if(view_pos > 0){
			if (view_pos > VIEW_ROWS) {
				view_pos -= VIEW_ROWS;
			} else {
				view_pos = 0;
			}
		}
		break;
	case 2:
		if (cur_pos < last_pos) {
			cur_pos = last_pos;
		} else if(view_pos + VIEW_ROWS < file_list_len){
			if (view_pos < file_list_len - VIEW_ROWS * 2){
				view_pos += VIEW_ROWS;
			} else {
				view_pos = file_list_len - VIEW_ROWS;
			}
		}
	}
}

void exit_with_prompt(int exit_code) {
	prt("press A to exit...");
	while (1) {
		swiWaitForVBlank();
		scanKeys();
		if (keysDown() & KEY_A) break;
	}
	exit(exit_code);
}

unsigned wait_keys(unsigned keys) {
	while (1) {
		swiWaitForVBlank();
		scanKeys();
		unsigned kd = keysDown();
		if (kd & keys) {
			return kd;
		}
	}
}

void walk_cb_lst_file(const char *name, int is_dir, void *p_param) {
	if (is_dir) {
		return;
	}
	name += sizeof(nand_root) - 1;
	iprtf("%s\n", name);
	fiprintf((FILE*)p_param, "%s\n", name);
}

void walk_cb_lst_dir(const char *name, int is_dir, void *p_param) {
	if (!is_dir) {
		return;
	}
	name += sizeof(nand_root) - 1;
	iprtf("%s\n", name);
	fiprintf((FILE*)p_param, "%s\n", name);
}

void walk_cb_sha1(const char *name, int is_dir, void *p_param) {
	if (is_dir) {
		return;
	}
	const char *rname = name + sizeof(nand_root) - 1;
	iprtf("%s", rname);
	unsigned char digest[SHA1_LEN];
	int sha1_ret = sha1_file(digest, name);
	iprtf(" %d\n", sha1_ret);
	if (sha1_ret < 0) {
		return;
	}
	for (unsigned i = 0; i < SHA1_LEN; ++i) {
		fiprintf((FILE*)p_param, "%02X", digest[i]);
	}
	fiprintf((FILE*)p_param, " *%s\n", rname);
}

void walk_cb_dump(const char *name, int is_dir, void *_) {
}

void menu_action(const char *name) {
	iprtf("dry run: %s\n", name);
	unsigned size;
	// dry run
	int ret = scripting(name, 1, &size);
	iprtf("dry run returned %d\n", ret);
	if (ret != 0) {
		return;
	}
	if (df(nand_root, 0) < size + RESERVE_FREE) {
		prt("insufficient NAND space\n");
		return;
	}
	prt("execute? Yes(A)/No(B)\n");
	if(wait_keys(KEY_A | KEY_B) & KEY_A) {
		ret = scripting(name, 0, 0);
		// TODO: some scripts might not induce writes
		++executions;
		iprtf("execution returned %d\n", ret);
		// maybe we should prompt to restore a NAND image
	}
}

void menu() {
	// list
	file_list_len = 0;
	listdir(list_dir, 0, file_list_add, 0);
	if (file_list_len == 0) {
		iprtf("no script in %s\n", list_dir);
		exit_with_prompt(-1);
	}
	// init menu
	view_pos = 0;
	cur_pos = 0;
	draw_file_list();
	while (1) {
		swiWaitForVBlank();
		scanKeys();
		uint32 keys = keysDown();
		int needs_redraw = 0;
		if (keys & KEY_B) {
			prt("unmount and quit(A)? cancel(B)\n");
			if (wait_keys(KEY_A | KEY_B) & KEY_A) {
				break;
			} else {
				prt("cancelled\n");
			}
		}else if(keys & (KEY_UP|KEY_DOWN|KEY_LEFT|KEY_RIGHT)){
			if (keys & KEY_UP) {
				menu_move(-1);
			} else if (keys & KEY_DOWN) {
				menu_move(1);
			} else if (keys & KEY_LEFT) {
				menu_move(-2);
			} else if (keys & KEY_RIGHT) {
				menu_move(2);
			}
			needs_redraw = 1;
		} else if (keys & KEY_A) {
			menu_action(file_list[view_pos + cur_pos].name);
		} else if ((keys & KEY_START)) {
			prt("\t(A) list NAND directories\n"
				"\t(X) list NAND files\n"
				"\t(Y) sha1 NAND files\n"
				"\t(B) cancel\n");
			unsigned keys = wait_keys(KEY_A | KEY_B | KEY_X | KEY_Y);
			if (keys & KEY_A) {
				FILE * f = fopen("nand_dirs.lst", "w");
				iprtf("walk returned %d\n", walk(nand_root, walk_cb_lst_dir, f));
				fclose(f);
			} else if (keys & KEY_X) {
				FILE * f = fopen("nand_files.lst", "w");
				iprtf("walk returned %d\n", walk(nand_root, walk_cb_lst_file, f));
				fclose(f);
			} else if (keys & KEY_Y) {
				FILE * f = fopen("nand_files.sha1", "w");
				iprtf("walk returned %d\n", walk(nand_root, walk_cb_sha1, f));
				fclose(f);
			} else {
				prt("cancelled\n");
			}
		}
		if (needs_redraw) {
			draw_file_list();
		}
	}
}

void set_scroll_callback(int x, int y, void *param) {
	bgSetScroll(*(int*)param, x, y);
	bgUpdate();
}

/* different modes:
	image mode, mount a valid native image
		if such image doesn't exist, prompt to create one
		test against NAND sector 0 and native IDs
		(TODO) update nand.sha1 upon quiting
	(DANGEROUS) direct mode, mounts real NAND
		(TODO) if any writes failed, prompt to restore a image as rescue
			so a valid native NAND image is required to enter direct mode
				valid: contains valid no$gba footer which can decrypt itself
				native: IDs identical to running hardware
	(DEBUG) image test mode, mount a valid image
		but not necessarily native
		this is for testing a foreign NAND image
	(DEBUG) direct test mode
		doesn't require a NAND image as rescue
		this is for testing on a B9S 3DS in TWL mode
*/
enum {
	MODE_IMAGE,
	MODE_DIRECT,
	MODE_IMAGE_TEST,
	MODE_DIRECT_TEST
};

int main(int argc, const char * const argv[]) {
	defaultExceptionHandler();

	videoSetModeSub(MODE_3_2D);
	videoSetMode(MODE_3_2D);
	vramSetBankC(VRAM_C_SUB_BG);
	vramSetBankA(VRAM_A_MAIN_BG);
	int bg0id = bgInitSub(3, BgType_Bmp8, BgSize_B8_256x256, 0, 0);
	int bg1id = bgInit(3, BgType_Bmp8, BgSize_B8_256x256, 0, 0);
	u16 *bg0 = bgGetGfxPtr(bg0id);
	u16 *bg1 = bgGetGfxPtr(bg1id);
	generate_ansi256_palette(BG_PALETTE_SUB);
	dmaCopy(BG_PALETTE_SUB, BG_PALETTE, 256 * 2);

	term_init(&t0, bg0, set_scroll_callback, &bg0id);
	term_init(&t1, bg1, set_scroll_callback, &bg1id);

	select_term(&t0);

	u32 bat_reg = getBatteryLevel();
	if (!(bat_reg & 1)) {
		iprtf("battery level too low: %08" PRIx32 "\n", bat_reg);
		exit_with_prompt(0);
	}

	int mode = MODE_IMAGE;

	if (argc > 1) {
		if (argc == 2 && !strcmp(argv[1], "image-test")) {
			prt("image test mode\n");
			mode = MODE_IMAGE_TEST;
		} else if (argc == 2 && !strcmp(argv[1], "direct-test")) {
			prt("direct test mode\n");
			mode = MODE_DIRECT_TEST;
		} else if (argc == 5 && !strcmp(argv[1], "aes-test")) {
			prt("AES test default\n");
			aes_test(atoi(argv[2]), argv[3], argv[4]);
			setCpuClock(false);
			prt("AES test clock low\n");
			aes_test(atoi(argv[2]), argv[3], argv[4]);
			setCpuClock(true);
			prt("AES test clock high\n");
			aes_test(atoi(argv[2]), argv[3], argv[4]);
			exit_with_prompt(0);
		}
	}

	int ret;

	prt("FAT init...");
	cpuStartTiming(0);
	ret = fatInitDefault();
	u32 td = timerTicks2usec(cpuEndTiming());
	if (!ret) {
		prt("\x1b[3D " BlkOnRed "failed!\n" Rst);
		exit_with_prompt(-1);
	} else {
		iprtf("\x1b[3D succeed, %" PRIu32 "us\n", td);
	}

	if (mode == MODE_IMAGE_TEST) {
		if ((ret = test_image_against_footer()) != 0) {
			exit_with_prompt(ret);
		}
		if ((ret = mount(0)) != 0) {
			exit_with_prompt(ret);
		}
	}else if(mode == MODE_DIRECT_TEST){
		if ((ret = get_ids()) != 0) {
			exit_with_prompt(ret);
		}
		int is3DS;
		ret = test_ids_against_nand(&is3DS);
		if (!is3DS) {
			prt("you should NOT use direct test mode in DSi\n");
			exit_with_prompt(0);
		}
		if (ret != 0) {
			prt("most likely Console ID is wrong\n");
			exit_with_prompt(ret);
		}
		prt(BlkOnRed "are you SURE to start direct test mode(A)? quit(B)?\n");
		if (wait_keys(KEY_A | KEY_B) & KEY_A) {
			if ((ret = mount(1)) != 0) {
				exit_with_prompt(ret);
			}
		} else {
			return 0;
		}
	}else{
		if ((ret = get_ids()) != 0) {
			exit_with_prompt(ret);
		}
		int is3DS;
		ret = test_ids_against_nand(&is3DS);
		if (is3DS) {
			prt("no point to use this on 3DS\n");
			exit_with_prompt(0);
		}
		if (ret != 0) {
			prt("most likely Console ID is wrong\n");
			exit_with_prompt(ret);
		}
		// TODO: also test against sha1
		if ((ret = test_image_against_nand()) != 0) {
			prt("you don't have a valid NAND backup, backup now? Yes(A)/No(B)\n");
			if (wait_keys(KEY_A | KEY_B) & KEY_A) {
				if ((ret = backup()) != 0) {
					prt("backup failed\n");
					exit_with_prompt(ret);
				}
			} else {
				exit_with_prompt(-1);
			}
		}
		// either way, we should have a valid native NAND image by now
		prt("mount image (A)? quit(B)?\n");
		unsigned keys = wait_keys(KEY_A | KEY_B | KEY_X);
		if (keys & KEY_B) {
			return 0;
		} else if(keys & KEY_A){
			mode = MODE_IMAGE;
		} else if (keys & KEY_X) {
			mode = MODE_DIRECT;
			prt(BlkOnRed "you are mounting NAND R/W DIRECTLY, EXERCISE EXTREME CAUTION\n");
		}
		if((ret = mount(mode ==  MODE_DIRECT ? 1 : 0)) != 0) {
			exit_with_prompt(ret);
		}
	}

	df(nand_root, 1);

	if ((ret = scripting_init()) != 0) {
		fatUnmount(nand_vol_name);
		exit_with_prompt(ret);
	}

	menu();

	fatUnmount(nand_vol_name);
	// TODO: in image mode, update sha1 if writes > 0
	// TODO: in direct mode, restore NAND image if anything bad happens
}

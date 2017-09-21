#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <nds.h>
#include <fat.h>
#include "utils.h"
#include "walk.h"
#include "nand.h"
#include "scripting.h"

#define SHA1_LEN 20

#define RESERVE_FREE (5 * 1024 * 1024)

PrintConsole topScreen;
PrintConsole bottomScreen;

extern const char nand_img_name[];

unsigned executions = 0;

const char nand_vol_name[] = "NAND";
const char nand_root[] = "NAND:/";

#define CONSOLE_WIDTH	32
#define CONSOLE_HEIGHT	23

#define Cls "\x1b[2J"
#define Rst "\x1b[0m"
// unfortunately background colors are not working
#define Blk "\x1b[40m"
#define Red "\x1b[41m"
#define Grn "\x1b[42m"
#define Ylw "\x1b[43m"
#define Blu "\x1b[44m"
#define Mag "\x1b[45m"
#define Cyn "\x1b[46m"
#define Wht "\x1b[47m"

typedef struct {
	const char *name;
	size_t size;
}file_list_item_t;

#define FILE_LIST_MAX 0x100

const char list_dir[] = "scripts/";
const char footer[] = "(A)select (B)quit";
file_list_item_t file_list[FILE_LIST_MAX];
unsigned file_list_len;
unsigned view_pos;
unsigned cur_pos;

#define VIEW_HEIGHT (CONSOLE_HEIGHT - 2)

void file_list_add(const char *name, size_t size, void *_) {
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

void draw_file_list() {
	// TODO: right align position
	iprintf(Cls Red "%s %u/%u\n", list_dir, view_pos + cur_pos + 1, file_list_len);
	for (unsigned i = 0; i < VIEW_HEIGHT; ++i) {
		if (view_pos + i < file_list_len) {
			iprintf(i == cur_pos ? Grn : Wht);
			file_list_item_t *item = &file_list[view_pos + i];
			// TODO: right align size
			iprintf("%s %u\n", item->name, item->size);
		} else {
			iprintf("\n");
		}
	}
	iprintf(Red "%s\n" Rst, footer);
}

void menu_move(int move) {
	unsigned last_pos = file_list_len < VIEW_HEIGHT ? file_list_len - 1 : VIEW_HEIGHT - 1;
	switch (move) {
	case -1:
		if (cur_pos > 0) {
			--cur_pos;
		} else {
			// TODO: move view
		}
		break;
	case 1:
		if (cur_pos < last_pos) {
			++cur_pos;
		} else {
		}
		break;
	case -2:
		if (cur_pos > 0) {
			cur_pos = 0;
		} else {
		}
		break;
	case 2:
		if (cur_pos < last_pos) {
			cur_pos = last_pos;
		} else {
		}
	}
}

void exit_with_prompt(int exit_code) {
	iprintf("press A to exit...");
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

void walk_cb_lst(const char *name, void *p_param) {
	iprintf("%s\n", name);
	fiprintf((FILE*)p_param, "%s\n", name);
}

void walk_cb_sha1(const char *name, void *p_param) {
	iprintf("%s", name);
	unsigned char digest[SHA1_LEN];
	int sha1_ret = sha1_file(digest, name);
	iprintf(" %d\n", sha1_ret);
	if (sha1_ret < 0) {
		return;
	}
	for (unsigned i = 0; i < SHA1_LEN; ++i) {
		fiprintf((FILE*)p_param, "%02X", digest[i]);
	}
	fiprintf((FILE*)p_param, " *%s\n", name);
}

void walk_cb_dump(const char *name, void *_) {
}

void menu_action(const char *name) {
	iprintf("dry run: %s\n", name);
	unsigned size;
	// dry run
	int ret = scripting(name, 1, &size);
	iprintf("dry run returned %d\n", ret);
	if (ret != 0) {
		return;
	}
	if (df(nand_root, 0) < size + RESERVE_FREE) {
		iprintf("insufficient NAND space\n");
		return;
	}
	iprintf("execute? Yes(A)/No(B)\n");
	if(wait_keys(KEY_A | KEY_B) & KEY_A) {
		ret = scripting(name, 0, 0);
		// TODO: some scripts might not induce writes
		++executions;
		iprintf("execution returned %d\n", ret);
		// maybe we should prompt to restore a NAND image
	}
}

void menu() {
	// list
	file_list_len = 0;
	listdir(list_dir, 0, file_list_add, 0);
	if (file_list_len == 0) {
		iprintf("no script in %s\n", list_dir);
		exit_with_prompt(-1);
	}
	// init menu
	consoleSelect(&topScreen);
	view_pos = 0;
	cur_pos = 0;
	draw_file_list();
	int needs_redraw = 0;
	while (1) {
		swiWaitForVBlank();
		scanKeys();
		uint32 keys = keysDown();
		consoleSelect(&bottomScreen);
		if (keys & KEY_B) {
			break;
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
		} else if ((keys & KEY_START) && (keys & KEY_L)) {
			FILE * f = fopen("nand_files.lst", "w");
			iprintf("walk returned %d\n", walk(nand_root, walk_cb_lst, f));
			fclose(f);
		} else if ((keys & KEY_START) && (keys & KEY_R)) {
			FILE * f = fopen("nand_files.sha1", "w");
			iprintf("walk returned %d\n", walk(nand_root, walk_cb_sha1, f));
			fclose(f);
		}
		if (needs_redraw) {
			consoleSelect(&topScreen);
			draw_file_list();
		}
	}
}

int main(int argc, const char * const argv[]) {
	defaultExceptionHandler();

	videoSetMode(MODE_0_2D);
	videoSetModeSub(MODE_0_2D);

	vramSetBankA(VRAM_A_MAIN_BG);
	vramSetBankC(VRAM_C_SUB_BG);

	consoleInit(&topScreen, 3, BgType_Text4bpp, BgSize_T_256x256, 31, 0, true, true);
	consoleInit(&bottomScreen, 3, BgType_Text4bpp, BgSize_T_256x256, 31, 0, false, true);

	consoleSelect(&bottomScreen);

	/* 3 modes:
		0, (RO) direct mode, mounts real NAND
			(TODO) if any writes failed, prompt to restore a image
				so a valid native NAND image is required to enter direct mode
					valid: contains valid no$gba footer which can decrypt itself
					native: IDs identical to running hardware
		1, image mode, mount a valid native image
			if such image doesn't exist, prompt to create one
			test against NAND sector 0 and native IDs
			(TODO) update nand.sha1 upon quiting
		2, (DEBUG) image test mode, mount a valid image
			but not necessarily native
			this is for testing a foreign NAND image
	*/

	int mode = 0;

	if (argc > 1) {
		for (unsigned i = 1; i < argc; ++i) {
			if (!strcmp(argv[i], "--img-test")) {
				iprintf("image test mode\n");
				mode = 2;
			}
		}
	}

	u32 bat_reg = getBatteryLevel();
	iprintf("battery: %08" PRIx32 "\n", bat_reg);

	iprintf("FAT init...");

	if (!fatInitDefault()) {
		iprintf("\x1b[3D failed!\n");
		exit_with_prompt(-1);
	} else {
		iprintf("\x1b[3D succeed\n");
	}

	int ret;
	if (mode == 2) {
		if ((ret = test_image_against_footer()) != 0) {
			exit_with_prompt(ret);
		}
		if ((ret = mount(0)) != 0) {
			exit_with_prompt(ret);
		}
	}else{
		if ((ret = get_ids()) != 0) {
			exit_with_prompt(ret);
		}
		int is3DS;
		ret = test_ids_against_nand(&is3DS);
		if (is3DS) {
			iprintf("no point to use this on 3DS\n");
			exit_with_prompt(0);
		}
		if (ret != 0) {
			iprintf("most likely Console ID is wrong\n");
			exit_with_prompt(ret);
		}
		// TODO: also test against sha1
		if ((ret = test_image_against_nand()) != 0) {
			iprintf("you don't have a valid NAND backup, backup now? Yes(A)/No(B)\n");
			if (wait_keys(KEY_A | KEY_B) & KEY_A) {
				if ((ret = backup()) != 0) {
					iprintf("backup failed\n");
					exit_with_prompt(ret);
				}
			} else {
				exit_with_prompt(-1);
			}
		}
		// either way, we should have a valid NAND image by now
		iprintf("image mode(A) or direct mode(X)?\n");
		if (wait_keys(KEY_A | KEY_X) & KEY_X) {
			mode = 0;
		} else {
			mode = 1;
		}
		if((ret = mount(mode == 0 ? 1 : 0)) != 0) {
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

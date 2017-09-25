#pragma once

#include <nds.h>
#include "font.h"

// written for NDS, should not be hard to port back to GBA

#define TERM_COLS (SCREEN_WIDTH / FONT_WIDTH)
#define TERM_ROWS (SCREEN_HEIGHT / FONT_HEIGHT)
#define TERM_MAX_CHARS (TERM_COLS * TERM_ROWS)

void generate_ansi256_palette(u16 *p);

typedef void(*set_scroll_cb_t)(int x, int y, void *cb_param);

#define TERM_ESC_ARG_LEN 0x10

typedef struct {
	u16 *bg;
	unsigned cur;
	unsigned color_fg;
	unsigned color_bg;
	u16 clut[FONT_WIDTH / sizeof(u16) * (1 << FONT_WIDTH)];
	unsigned scroll_pos;
	set_scroll_cb_t set_scroll_cb;
	void *set_scroll_cb_param;
	int esc_state;
	unsigned esc_argv[TERM_ESC_ARG_LEN];
	unsigned esc_argc;
}term_t;

enum {
	TERM_ESTATE_INIT,
	TERM_ESTATE_B2,
	TERM_ESTATE_CSI,
};

enum {
	TERM_COLOR,
	TERM_FG_COLOR,
	TERM_BG_COLOR,
	TERM_MOVE,
	TERM_MOVE_COL,
	TERM_MOVE_ROW,
	TERM_SET_COL,
	TERM_SET_ROW,
};

enum {
	COLOR_FG_DEF = 7,
	COLOR_BG_DEF = 0,
};

void clr_bg(void *bg, unsigned height, u8 color);

void term_init(term_t *t, u16 *fb, set_scroll_cb_t cb, void *cb_param);

void term_rst(term_t *t, u8 fg, u8 bg);

void term_prt(term_t *t, const char *string);

void term_ctl(term_t *t, int ctl_code, int param0, int param1);

void term_raw(term_t *t, char c);

#pragma once

#include <nds.h>
#include "font.h"

#define TERM_WIDTH (SCREEN_WIDTH / FONT_WIDTH)
#define TERM_HEIGHT (SCREEN_HEIGHT / FONT_HEIGHT)
#define TERM_MAX_CHARS (TERM_WIDTH * TERM_HEIGHT)

typedef u16 color_t;

void generate_ansi256_palette(color_t *p);

typedef struct {
	u16 *fb;
	unsigned cur;
	u8 cur_fg;
	u8 cur_bg;
}term_t;

enum {
	TERM_COLOR,
	TERM_BG_COLOR,
	TERM_MOVE_X,
	TERM_MOVE_Y,
};

void clr_screen(void *fb, u8 color);

void term_init(term_t *t, u16 *fb);

void term_rst(term_t *t, u8 fg, u8 bg);

void term_prt(term_t * t, const char *string);

void term_ctl(term_t *t, int ctl_code, int ctl_param);

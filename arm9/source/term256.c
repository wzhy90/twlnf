#include <nds.h>
#include <assert.h>
#include "term256.h"

#ifdef TERM256_DEBUG
void dbg_iprtf(const char *fmt, ...)
	_ATTRIBUTE ((__format__ (__printf__, 1, 2)));
#endif

#define BG_WIDTH 256
#define BG_HEIGHT 256

#define TERM_WIDTH (FONT_WIDTH * TERM_COLS)
#define TERM_HEIGHT (FONT_HEIGHT * TERM_ROWS)

// default scroll x, center, border both side
#define SCROLL_X0 ((TERM_WIDTH - SCREEN_WIDTH) / 2)
// default scroll y, touch bottom to hide text below on bg, border(previous lines) on top
#define SCROLL_Y0 ((TERM_HEIGHT - SCREEN_HEIGHT))

// use extra bg space to do native scroll, if possible
#define BG_ROWS (BG_HEIGHT / FONT_HEIGHT)
#define HW_SCROLL_STEPS (BG_ROWS - TERM_ROWS)

// make VC happy
#ifdef _MSC_VER
#define ITCM_CODE
#define UNROLL
#else
#define UNROLL __attribute__((optimize("unroll-loops")))
#endif

#define RGB(r, g, b) RGB15(r, g, b)
#define RBITS 5
#define RMAX (1 << RBITS)
#define GBITS 5
#define GMAX (1 << GBITS)
#define BBITS 5
#define BMAX (1 << BBITS)

// https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
void generate_ansi256_palette(u16 *p) {
	// maybe I should use round to improve precision
	// standard colors
	*p++ = RGB(0, 0, 0);
	*p++ = RGB(RMAX >> 1, 0, 0);
	*p++ = RGB(0, GMAX >> 1, 0);
	*p++ = RGB(RMAX >> 1, GMAX >> 1, 0);
	*p++ = RGB(0, 0, BMAX >> 1);
	*p++ = RGB(RMAX >> 1, 0, BMAX >> 1);
	*p++ = RGB(0, GMAX >> 1, BMAX >> 1);
	*p++ = RGB((RMAX * 3) >> 2, (GMAX * 3) >> 2, (BMAX * 3) >> 2);
	// high-intensity colors
	*p++ = RGB(RMAX >> 1, GMAX >> 1, BMAX >> 1);
	*p++ = RGB(RMAX - 1, 0, 0);
	*p++ = RGB(0, GMAX - 1, 0);
	*p++ = RGB(RMAX - 1, GMAX - 1, 0);
	*p++ = RGB(0, 0, BMAX - 1);
	*p++ = RGB(RMAX - 1, 0, BMAX - 1);
	*p++ = RGB(0, GMAX - 1, BMAX - 1);
	*p++ = RGB(RMAX - 1, GMAX - 1, BMAX - 1);
	// 216 colors, 6 * 6 * 6
	unsigned rsteps[6] = { 0, (RMAX - 1) / 5, (RMAX - 1) * 2 / 5,
		(RMAX - 1) * 3 / 5, (RMAX - 1) * 4 / 5, RMAX - 1 };
	unsigned gsteps[6] = { 0, (GMAX - 1) / 5, (GMAX - 1) * 2 / 5,
		(GMAX - 1) * 3 / 5, (GMAX - 1) * 4 / 5, GMAX - 1 };
	unsigned bsteps[6] = { 0, (BMAX - 1) / 5, (BMAX - 1) * 2 / 5,
		(BMAX - 1) * 3 / 5, (BMAX - 1) * 4 / 5, BMAX - 1 };
	// how do I tell gcc not to unroll this?
	for (unsigned r = 0; r < 6; ++r) {
		for (unsigned g = 0; g < 6; ++g) {
			for (unsigned b = 0; b < 6; ++b) {
				*p++ = RGB(rsteps[r], gsteps[g], bsteps[b]);
			}
		}
	}
	// 24 gray scales, not including full white and full black, so 25 steps
	for (unsigned j = 1; j < 25; ++j) {
		*p++ = RGB((RMAX - 1) * j / 25, (GMAX - 1) * j / 25, (BMAX - 1) * j / 25);
	}
}

static_assert(FONT_WIDTH == 6, "this thing can only handle FONT_WIDTH == 6");
#ifdef ARM9
ITCM_CODE
#endif
static void term_gen_clut(term_t *t) {
	u16 *p = t->clut;
	for (unsigned i = 0; i < (1 << FONT_WIDTH); ++i) {
		*p++ = (i & 0x20 ? t->color_fg : t->color_bg) | ((i & 0x10 ? t->color_fg : t->color_bg) << 8);
		*p++ = (i & 0x08 ? t->color_fg : t->color_bg) | ((i & 0x04 ? t->color_fg : t->color_bg) << 8);
		*p++ = (i & 0x02 ? t->color_fg : t->color_bg) | ((i & 0x01 ? t->color_fg : t->color_bg) << 8);
	}
}

#ifdef ARM9
ITCM_CODE
#endif
UNROLL
static inline void write_char(term_t *t, unsigned x, unsigned y, unsigned char c, unsigned char color, unsigned char bg_color) {
	const unsigned char *g = font + c * FONT_HEIGHT;
	u16 *p = t->bg + (y * BG_WIDTH + x) / 2;
	for (unsigned fy = 0; fy < FONT_HEIGHT; ++fy) {
		u16 *c = t->clut + (*g++) * FONT_WIDTH / sizeof(u16);
		*p++ = *c++;
		*p++ = *c++;
		*p = *c;
		p += BG_WIDTH / 2 - 2;
	}
}

void clr_bg(void *bg, unsigned height, u8 color) {
	u32 *p = (u32*)bg;
	u32 *p_end = p + (BG_WIDTH * height / sizeof(u32));
	u32 c4 = color | color << 8 | color << 16 | color << 24;
	while (p < p_end) {
		*p++ = c4; *p++ = c4; *p++ = c4; *p++ = c4;
		*p++ = c4; *p++ = c4; *p++ = c4; *p++ = c4;
	}
}

void term_rst(term_t *t, u8 fg, u8 bg) {
	t->cur = 0;
	if (t->scroll_pos != 0) {
		t->scroll_pos = 0;
		if (t->set_scroll_cb) {
			t->set_scroll_cb(SCROLL_X0, SCROLL_Y0, t->set_scroll_cb_param);
		}
	}
	if (fg != t->color_fg || bg != t->color_bg) {
		t->color_fg = fg;
		t->color_bg = bg;
		term_gen_clut(t);
	}
	t->esc_state = TERM_ESTATE_INIT;
	clr_bg(t->bg, TERM_HEIGHT, bg);
}

void term_init(term_t *t, u16 *bg, set_scroll_cb_t cb, void *cb_param) {
	t->bg = bg;
	t->set_scroll_cb = cb;
	t->set_scroll_cb_param = cb_param;
	t->scroll_pos = 1; // trigger scroll_cb in term_rst
	term_rst(t, COLOR_FG_DEF, COLOR_BG_DEF);
}

static_assert((FONT_HEIGHT * BG_WIDTH) % sizeof(u32) == 0, "this thing can't handle this");
static_assert((FONT_HEIGHT * BG_WIDTH / sizeof(u32)) % 8 == 0, "you can't unroll that much");
#ifdef ARM9
ITCM_CODE
#endif
void scroll(term_t *t) {
	if (t->set_scroll_cb == 0) {
		// no hardware scroll, full software scroll
		u32 *p = (u32*)t->bg;
		u32 *p_end = p + (FONT_HEIGHT * BG_WIDTH / sizeof(u32) * (TERM_ROWS - 1));
		u32 *p_src = p + (FONT_HEIGHT * BG_WIDTH / sizeof(u32));
		while (p < p_end) {
			*p++ = *p_src++; *p++ = *p_src++; *p++ = *p_src++; *p++ = *p_src++;
			*p++ = *p_src++; *p++ = *p_src++; *p++ = *p_src++; *p++ = *p_src++;
		}
		while (p < p_src) {
			*p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
			*p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
		}
		t->cur -= TERM_COLS;
	} else if (t->scroll_pos < HW_SCROLL_STEPS){
		// hardware scroll, but clear the row just showed up
		u32 *p = (u32*)t->bg + (FONT_HEIGHT * BG_WIDTH / sizeof(u32) * (TERM_ROWS + t->scroll_pos));
		u32 *p_end = p + (FONT_HEIGHT * BG_WIDTH / sizeof(u32));
		while (p < p_end) {
			*p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
			*p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
		}
		t->scroll_pos += 1;
		t->set_scroll_cb(SCROLL_X0, SCROLL_Y0 + FONT_HEIGHT * t->scroll_pos, t->set_scroll_cb_param);
		t->cur -= TERM_COLS;
	} else {
		// hardware scroll end of bg, reset back to top, like software scroll, just different positions
		u32 *p = (u32*)t->bg;
		u32 *p_end = p + (FONT_HEIGHT * BG_WIDTH / sizeof(u32) * (TERM_ROWS - 1));
		u32 *p_src = p + (FONT_HEIGHT * BG_WIDTH / sizeof(u32) * (BG_ROWS - TERM_ROWS + 1));
		while (p < p_end) {
			*p++ = *p_src++; *p++ = *p_src++; *p++ = *p_src++; *p++ = *p_src++;
			*p++ = *p_src++; *p++ = *p_src++; *p++ = *p_src++; *p++ = *p_src++;
		}
		p_end = p + (FONT_HEIGHT * BG_WIDTH / sizeof(u32));
		while (p < p_end) {
			*p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
			*p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
		}
		t->cur -= TERM_COLS;
		t->scroll_pos = 0;
		t->set_scroll_cb(SCROLL_X0, SCROLL_Y0, t->set_scroll_cb_param);
	}
}

void term_ctl(term_t *t, int ctl_code, int param0, int param1) {
	switch (ctl_code) {
	case TERM_COLOR:
		if (t->color_fg != param0 || t->color_bg != param1) {
			t->color_fg = param0;
			t->color_bg = param1;
			term_gen_clut(t);
		}
		break;
	case TERM_FG_COLOR:
		if (t->color_fg != param0) {
			t->color_fg = param0;
			term_gen_clut(t);
		}
		break;
	case TERM_BG_COLOR:
		if (t->color_bg != param0) {
			t->color_bg = param0;
			term_gen_clut(t);
		}
		break;
	case TERM_MOVE_COL:
	case TERM_SET_COL: {
		unsigned x_pos = t->cur % TERM_COLS;
		unsigned min_cur = t->cur - x_pos;
		unsigned max_cur = t->cur - x_pos + TERM_COLS - 1;
		if (max_cur > TERM_MAX_CHARS) {
			max_cur = TERM_MAX_CHARS;
		}
		if (ctl_code == TERM_MOVE_COL) {
			t->cur += param0;
		} else {
			t->cur = min_cur + param0;
		}
		if (t->cur < min_cur) {
			t->cur = min_cur;
		} else if(t->cur > max_cur){
			t->cur = max_cur;
		}
		break;
	} case TERM_MOVE_ROW:
	case TERM_SET_ROW: {
		unsigned min_cur = t->cur % TERM_COLS;
		unsigned max_cur = TERM_COLS * (TERM_ROWS - 1) + min_cur;
		if (ctl_code == TERM_MOVE_ROW) {
			t->cur += param0 * TERM_COLS;
		} else {
			t->cur = (t->cur % TERM_COLS) + (param0 * TERM_COLS);
		}
		if (t->cur < min_cur) {
			t->cur = min_cur;
		} else if (t->cur > max_cur) {
			t->cur = max_cur;
		}
		break;
	}case TERM_MOVE:{
		if (param0 < 0) {
			param0 = 0;
		} else if (param1 > TERM_ROWS - 1) {
			param0 = TERM_ROWS - 1;
		}
		if (param1 < 0) {
			param1 = 0;
		} else if (param1 > TERM_COLS - 1) {
			param1 = TERM_COLS - 1;
		}
		t->cur = param0 * TERM_COLS + param1;
		break;
	} default:
		break;
	}
}

// print a raw character, even \x00 or \xff
void term_raw(term_t *t, char c) {
#ifdef TERM256_DEBUG
	if (t->cur == TERM_MAX_CHARS) {
#else
	if (t->cur >= TERM_MAX_CHARS) {
#endif
		scroll(t);
	}
	write_char(t,
		(t->cur % TERM_COLS) * FONT_WIDTH,
		((t->cur / TERM_COLS) + t->scroll_pos) * FONT_HEIGHT,
		c, t->color_fg, t->color_bg);
	++t->cur;
}

/*
our ANSI ESC state machine only supports (some) CSI
	either two bytes \x1b(ESC/27/033)\x5b([/91/133) or single byte \x9b(155/233)
	doesn't support any other Non-CSI \x1b\x40~\x5f or \x80~\x9f
CSI codes:
https://en.wikipedia.org/wiki/ANSI_escape_code#CSI_codes
	CSI n 'ABCD'	CUU/D/F/B, cursor movement
	CSI n ; m 'H'	CUP, cursor position
	CSI n 'J'		ED, erase, only implemented n = 2 (entire screen)
	CSI n ; m 'f'	HVP, horizontal / vertical position, same as CUP
	CSI n ; ... 'm'	SGR, select graphics rendition
SGR codes, basically, only colors supported:
https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
	0			reset
	1			bold, actually, promote text color from 0~7 to 8~15
	7			reverse text/background color
	30~37/40~47	text/background color from palette 0~7
	38/48;5;n	text/background color, extended, from palette 0~255
	39/49		default text/background color
*/
enum {
	SGR_INIT,
	SGR_FG_EXT,
	SGR_FG_EXT5,
	SGR_BG_EXT,
	SGR_BG_EXT5
};
enum {
	SGR_NO_ERR = 0,
	SGR_UNSUPPORTED,
	SGR_UNSUPPORTED_EXT
};
void term_sgr(term_t *t) {
	// SGR has no use outside CSI, but too big so it's separated
	int sgr = SGR_INIT, err = 0;
	unsigned color_fg = t->color_fg, color_bg = t->color_bg;
	unsigned tmp;
	// dbg_iprtf("SGR argc = %d\n", t->esc_argc);
	// beware how args are handled, <= is correct
	for (unsigned i = 0; i <= t->esc_argc; ++i) {
		int arg = t->esc_argv[i];
		// dbg_iprtf("\tSGR arg = %d\n", arg);
		switch (sgr) {
		case SGR_INIT:
			switch (arg) {
			case 0:
				color_fg = COLOR_FG_DEF;
				color_bg = COLOR_BG_DEF;
				break;
			case 1:
				if (color_fg >= 0 && color_fg <= 7) {
					color_fg += 8;
				}
				break;
			case 7:
				tmp = color_fg;
				color_fg = color_bg;
				color_bg = tmp;
				break;
			case 38:
				sgr = SGR_FG_EXT;
				break;
			case 39:
				color_fg = COLOR_FG_DEF;
				break;
			case 48:
				sgr = SGR_BG_EXT;
				break;
			case 49:
				color_bg = COLOR_BG_DEF;
				break;
			default:
				if (arg >= 30 && arg <= 37) {
					color_fg = arg - 30;
				} else if (arg >= 40 && arg <= 47) {
					color_bg = arg - 40;
				}
			}
			break;
		case SGR_FG_EXT:
			if (arg == 5) {
				sgr = SGR_FG_EXT5;
			} else {
				// unsupported ext modes
				// so we don't know how to interpret the rest
				err = SGR_UNSUPPORTED_EXT;
			}
			break;
		case SGR_BG_EXT:
			if (arg == 5) {
				sgr = SGR_BG_EXT5;
			} else {
				err = SGR_UNSUPPORTED_EXT;
			}
			break;
		case SGR_FG_EXT5:
			color_fg = arg & 0xff;
			sgr = SGR_INIT;
			break;
		case SGR_BG_EXT5:
			color_bg = arg & 0xff;
			sgr = SGR_INIT;
			break;
		default:
			err = SGR_UNSUPPORTED;
		}
		if (err) {
			// dbg_iprtf("SGR: err %d\n", err);
			break;
		}
	}
	term_ctl(t, TERM_COLOR, color_fg, color_bg);
}

enum {
	CSI_CUU = 'A',
	CSI_CUD = 'B',
	CSI_CUF = 'C',
	CSI_CUB = 'D',
	CSI_CUP = 'H',
	CSI_ED = 'J',
	CSI_HVP = 'f',
	CSI_SGR = 'm'
};
// return 1 if consumed
int term_esc(term_t *t, char c) {
	switch (t->esc_state) {
	case TERM_ESTATE_INIT:
		switch (c) {
		case '\x1b':
			t->esc_state = TERM_ESTATE_B2;
			return 1;
		case '\x9b':
			t->esc_state = TERM_ESTATE_CSI;
			t->esc_argc = 0;
			t->esc_argv[0] = 0;
			return 1;
		default:
			return 0;
		}
	case TERM_ESTATE_B2: // waiting for byte 2 after ESC
		if (c == '[') {
			t->esc_state = TERM_ESTATE_CSI;
			t->esc_argc = 0;
			t->esc_argv[0] = 0;
			return 1;
		} else {
			// not CSI, not supported
			t->esc_state = TERM_ESTATE_INIT;
			return 0;
		}
	case TERM_ESTATE_CSI:
		if (c >= 0x40 && c <= 0x7e) {
			// this is the end of escape sequence
			switch (c) {
			case CSI_CUU:
				term_ctl(t, TERM_MOVE_ROW, -t->esc_argv[0], 0);
				break;
			case CSI_CUD:
				term_ctl(t, TERM_MOVE_ROW, t->esc_argv[0], 0);
				break;
			case CSI_CUF:
				term_ctl(t, TERM_MOVE_COL, t->esc_argv[0], 0);
				break;
			case CSI_CUB:
				term_ctl(t, TERM_MOVE_COL, -t->esc_argv[0], 0);
				break;
			case CSI_CUP:
			case CSI_HVP:
				if (t->esc_argc == 1) {
					// they're 1 based
					term_ctl(t, TERM_MOVE, t->esc_argv[0] - 1, t->esc_argv[1] - 1);
				}
				break;
			case CSI_ED:
				if (t->esc_argv[0] == 2) {
					term_rst(t, t->color_fg, t->color_bg);
					term_ctl(t, TERM_MOVE, 0, 0);
				}
				break;
			case CSI_SGR:
				term_sgr(t);
				break;
			default:
				// not supported
				break;
			}
			t->esc_state = TERM_ESTATE_INIT;
			return 1;
		} else if(t->esc_argc < TERM_ESC_ARG_LEN){
			// handle the char as arg
			if (c >= '0' && c <= '9') {
				if (t->esc_argc < TERM_ESC_ARG_LEN) {
					t->esc_argv[t->esc_argc] = t->esc_argv[t->esc_argc] * 10 + c - '0';
				}
			} else if (c == ';') { // the delimiter
				++ t->esc_argc;
				if (t->esc_argc < TERM_ESC_ARG_LEN) {
					t->esc_argv[t->esc_argc] = 0;
				}
			} else {
				// anything other than 0~9 or ; is dropped
			}
			return 1;
		} else {
			// if the arg is too long they're just silently dropped
			return 1;
		}
	}
	return 0;
}

#define TAB_WIDTH 4

// handles some special characters
void term_prt(term_t *t, const char *s) {
	unsigned char c;
	while ((c = *(const unsigned char*)s++) != 0) {
		if (term_esc(t, c)) {
			continue;
		}
		if (c == '\n') {
			unsigned col = t->cur % TERM_COLS;
			if (col != 0) {
				// do not allow empty line
				// also, new line never causes scroll
				t->cur += TERM_COLS - col;
			}
		} else if (c == '\r') {
			t->cur -= t->cur % TERM_COLS;
		} else if (c == '\t') {
			unsigned col = t->cur % TERM_COLS;
			unsigned new_col = col + TAB_WIDTH;
			new_col -= new_col % TAB_WIDTH;
			if (new_col > TERM_COLS) {
				new_col = TERM_COLS;
			}
			new_col -= col; // becomes d_col now
			if (new_col > 0) {
				if (t->cur == TERM_MAX_CHARS) {
					scroll(t);
				}
				t->cur += new_col;
			}
		} else {
			term_raw(t, c);
		}
	}
}

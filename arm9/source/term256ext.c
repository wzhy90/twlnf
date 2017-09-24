
#include <stdio.h>
#include <stdarg.h>
#include "term256.h"

static term_t *current_term;

void select_term(term_t *t) {
	current_term = t;
}

// do not print too long
#define STR_BUF_LEN 0x200
char str_buf[STR_BUF_LEN];

void iprtf(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vsniprintf(str_buf, STR_BUF_LEN, fmt, args);
	va_end(args);
	term_prt(current_term, str_buf);
}

void prtf(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vsnprintf(str_buf, STR_BUF_LEN, fmt, args);
	va_end(args);
	term_prt(current_term, str_buf);
}

void prt(const char *s) {
	term_prt(current_term, s);
}

#pragma once

#include "term256.h"
 
void select_term(term_t *t);

void iprtf(const char *fmt, ...)
	_ATTRIBUTE ((__format__ (__printf__, 1, 2)));

void prtf(const char *fmt, ...)
	_ATTRIBUTE ((__format__ (__printf__, 1, 2)));

void prt(const char *s);


#include <stdio.h>
#include <string.h>
#include "utils.h"

#define LINE_BUF_LEN 0x80

static void convert_backslash(char *p) {
	while (*p) {
		if (*p == '\\') {
			*p = '/';
		}
		++p;
	}
}

int sumfile_parser(const char *filename, unsigned hashlen,
	void(*callback)(const char*, const unsigned char*, void*), void *p_cb_param) {
	FILE *f = fopen(filename, "r");
	char line_buf[LINE_BUF_LEN];
	int irregular = 0;
	while (fgets(line_buf, LINE_BUF_LEN, f) != 0) {
		size_t len = strlen(line_buf);
		// it looks like fgets only handles 0a
		// in case of 0d0a, the line ends with 0d0a
		// in case of 0a0d, the 0d is at the beginning of next line
		/* 
		iprintf("len: %u\n", len);
		printBytes(line_buf, len);
		iprintf("\n");
		*/
		// at least one character for the name
		if (len < hashlen * 2 + 2 + 1) {
			++irregular;
			continue;
		}
		// only allow binary mode
		if (line_buf[hashlen * 2] != ' ' || line_buf[hashlen * 2 + 1] != '*') {
			++irregular;
			continue;
		}
		if (hexToBytes((unsigned char*)line_buf, hashlen, line_buf) != 0) {
			++irregular;
			continue;
		}
		// remove trailing LF and CRLF
		if (line_buf[len - 1] == 0x0a) {
			if (line_buf[len - 2] == 0x0d) {
				line_buf[len - 2] = 0;
			} else {
				line_buf[len - 1] = 0;
			}
		}
		char *name = &line_buf[hashlen * 2 + 2];
		convert_backslash(name);
		callback(name, (unsigned char*)line_buf, p_cb_param);
	}
	return irregular;
}

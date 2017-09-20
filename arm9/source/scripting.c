
#include <nds.h>
#include <stdio.h>
#include <string.h>
#include "common.h"
#include "utils.h"
#include "scripting.h"

#define LINE_BUF_LEN 0x100
char *line_buf = 0;

#define FILE_BUF_LEN (128 << 10)
u8* file_buf = 0;

int scripting_init() {
	if (file_buf == 0) {
		file_buf = (u8*)memalign(32, FILE_BUF_LEN);
	}
	if (line_buf == 0) {
		line_buf = (char*)malloc(LINE_BUF_LEN);
	}
	if (file_buf == 0 || line_buf == 0) {
		iprintf("failed to alloc buffer\n");
		return -1;
	} else {
		return 0;
	}
}

static void convert_backslash(char *p) {
	while (*p) {
		if (*p == '\\') {
			*p = '/';
		}
		++p;
	}
}

// returns size hashed, -1 if failed to open
int sha1_file(void *digest, const char *name) {
	FILE *f = fopen(name, "r");
	if (f == 0) {
		return -1;
	}
	swiSHA1context_t ctx;
	ctx.sha_block = 0;
	swiSHA1Init(&ctx);
	int size = 0;
	while (1) {
		size_t read = fread(file_buf, 1, FILE_BUF_LEN, f);
		if (read == 0) {
			break;
		}
		size += read;
		swiSHA1Update(&ctx, file_buf, read);
		if (read < FILE_BUF_LEN) {
			break;
		}
	}
	fclose(f);
	swiSHA1Final(digest, &ctx);
	return size;
}

int scripting(const char *filename, int dry_run){
	FILE *f = fopen(filename, "r");
	unsigned irregular = 0;
	unsigned size = 0;
	unsigned missing = 0;
	unsigned wrong = 0;
	unsigned check = 0;
	while (fgets(line_buf, LINE_BUF_LEN, f) != 0) {
		size_t len = strlen(line_buf);
		// it looks like fgets only handles 0a
		// in case of 0d0a, the line ends with 0d0a
		// in case of 0a0d, the 0d is at the beginning of next line
		/* 
		iprintf("len: %u\n", len);
		print_bytes(line_buf, len);
		iprintf("\n");
		*/
		// line starts with # was considered comment
		if (line_buf[0] == '#') {
			continue;
		}
		// at least one character for the name
		if (len < SHA1_LEN * 2 + 2 + 1) {
			++irregular;
			continue;
		}
		// only allow binary mode
		if (line_buf[SHA1_LEN * 2] != ' ' || line_buf[SHA1_LEN * 2 + 1] != '*') {
			++irregular;
			continue;
		}
		// reuse hex string location to store the binary form
		if (hex2bytes((unsigned char*)line_buf, SHA1_LEN, line_buf) != 0) {
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
		char *name = &line_buf[SHA1_LEN * 2 + 2];
		convert_backslash(name);
		// the hex string is just twice as long
		iprintf("%s ", name);
		int sha1_ret = sha1_file(&line_buf[SHA1_LEN], name);
		if (sha1_ret == -1) {
			iprintf("missing\n");
			++missing;
		} else {
			size += sha1_ret;
			if (memcmp(line_buf, &line_buf[SHA1_LEN], SHA1_LEN)) {
				iprintf("wrong\n");
				++wrong;
			} else {
				iprintf("OK\n");
				++check;
			}
		}
	}
	iprintf("%u/%u OK/All, %u bytes\n", check, check + missing + wrong, size);
	if (missing + wrong > 0) {
		iprintf("%u wrong, %u missing\n", wrong, missing);
	}
	if (irregular > 0) {
		iprintf("%u irregular lines\n", irregular);
	}

	return - irregular - missing - wrong;
}

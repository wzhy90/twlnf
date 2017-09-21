
#include <nds.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "common.h"
#include "utils.h"
#include "walk.h"
#include "scripting.h"

extern const char nand_root[];

#define LINE_BUF_LEN 0x100
static char line_buf[LINE_BUF_LEN];
static char name_buf[LINE_BUF_LEN];

#define FILE_BUF_LEN (128 << 10)
static u8* file_buf = 0;

int scripting_init() {
	if (file_buf == 0) {
		file_buf = (u8*)memalign(32, FILE_BUF_LEN);
	}
	if (file_buf == 0) {
		iprintf("failed to alloc buffer\n");
		return -1;
	} else {
		return 0;
	}
}

int is_whitespace(char c) {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

const char * ltrim(const char *s) {
	while (*s) {
		if (is_whitespace(*s)) {
			++s;
		} else {
			break;
		}
	}
	return s;
}

char * trim(char *s, unsigned *p_len) {
	size_t l = strlen(s);
	unsigned i;
	for (i = l - 1; i >= 0; --i) {
		if (is_whitespace(s[i])) {
			s[i] = 0;
		} else {
			break;
		}
	}
	if (i == 0) {
		*p_len = 0;
		return s;
	} else {
		unsigned j;
		for (j = 0; j < i; ++j) {
			if (!is_whitespace(s[j])) {
				break;
			}
		}
		*p_len = i - j + 1;
		return &s[j];
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

static const char *cmd_strs[] = {
	"file_exist",
	"dir_exist",
	"rm"
};

enum {
	CMD_FILE_EXIST,
	CMD_DIR_EXIST,
	CMD_RM
};

// check commands runs in dry run 
int cmd_is_chk[] = {
	1,
	1,
	0
};

enum {
	NO_ERR = 0,
	ERR_NOT_CMD = -1,
	ERR_CMD_FAIL = -2
};

static int cmd_exist(const char * arg, unsigned fmt) {
	struct stat s;
	iprintf("%s", arg);
	sniprintf(name_buf, LINE_BUF_LEN, "%s%s", nand_root, arg);
	if (stat(name_buf, &s) == 0 && (s.st_mode & S_IFMT) == fmt) {
		iprintf(" exist\n");
		return NO_ERR;
	} else {
		iprintf(" doesn't exist\n");
		return ERR_CMD_FAIL;
	}
}

static int cmd_rm(const char * arg) {
	sniprintf(name_buf, LINE_BUF_LEN, "%s%s", nand_root, arg);
	iprintf("not implemented\n");
	return NO_ERR;
}

static int execute_cmd(const char * line, unsigned len, int dry_run) {
	unsigned cmd;
	const char * arg = 0;
	for (cmd = 0; cmd < sizeof(cmd_strs) / sizeof(cmd_strs[0]); ++cmd) {
		const char* cmd_str = cmd_strs[cmd];
		unsigned cmd_len = strlen(cmd_str);
		if (len <= cmd_len) { // cmds always comes with parameter, so just equal is not OK
			continue;
		}
		if (!strncmp(cmd_str, line, cmd_len) && is_whitespace(line[cmd_len])) {
			arg = ltrim(&line[cmd_len + 1]);
			break;
		}
	}
	if (arg == 0) {
		return ERR_NOT_CMD;
	}
	if (dry_run == cmd_is_chk[cmd]) {
		switch (cmd) {
		case CMD_FILE_EXIST:
			return cmd_exist(arg, S_IFREG);
		case CMD_DIR_EXIST:
			return cmd_exist(arg, S_IFDIR);
		case CMD_RM:
			return cmd_rm(arg);
		}
	}
	return NO_ERR;
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

// this is evolved from parse_sha1sum so the structure is a bit strange
int scripting(const char *filename, int dry_run){
	FILE *f = fopen(filename, "r");
	unsigned irregular = 0;
	unsigned size = 0;
	unsigned missing = 0;
	unsigned wrong = 0;
	unsigned check = 0;
	while (fgets(line_buf, LINE_BUF_LEN, f) != 0) {
		unsigned len;
		char *line = trim(line_buf, &len);
		// lines start with # are ignored as comment
		if (len == 0 || line[0] == '#') {
			continue;
		}
		iprintf("DEBUG: %s\n", line);
		// try to run it as a cmd
		int exe_ret = execute_cmd(line, len, dry_run);
		if (exe_ret == NO_ERR) {
			continue;
		} else if (exe_ret == ERR_CMD_FAIL) {
			return exe_ret;
		} else if (exe_ret == ERR_NOT_CMD) {
			// then it's considered a SHA1 line
			// at least one character for the name
			if (len < SHA1_LEN * 2 + 2 + 1) {
				++irregular;
				continue;
			}
			// only allow binary mode
			if (line[SHA1_LEN * 2] != ' ' || line[SHA1_LEN * 2 + 1] != '*') {
				++irregular;
				continue;
			}
			// reuse hex string location to store the binary form
			// hex2bytes can work in place
			if (hex2bytes((unsigned char*)line, SHA1_LEN, line) != 0) {
				++irregular;
				continue;
			}
			// prepare name
			char *name = &line[SHA1_LEN * 2 + 2];
			convert_backslash(name);
			iprintf("%s ", name);
			// hash
			unsigned char digest[SHA1_LEN];
			if (dry_run) {
				int sha1_ret = sha1_file(digest, name);
				if (sha1_ret == -1) {
					iprintf("missing\n");
					++missing;
				} else {
					size += sha1_ret;
					if (memcmp(line, digest, SHA1_LEN)) {
						iprintf("wrong\n");
						++wrong;
					} else {
						iprintf("OK\n");
						++check;
					}
				}
			}
		} else {
			// should not happen
		}
	}
	iprintf("%u/%u OK/All, %u bytes\n", check, check + missing + wrong, size);
	if (missing + wrong > 0) {
		iprintf("%u wrong, %u missing\n", wrong, missing);
	}
	if (irregular > 0) {
		iprintf("%u irregular lines\n", irregular);
	}

	return irregular + missing + wrong;
}

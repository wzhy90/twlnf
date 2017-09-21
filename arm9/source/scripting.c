
#include <nds.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "common.h"
#include "utils.h"
#include "scripting.h"

extern const char nand_root[];
extern const char list_dir[];

#define LINE_BUF_LEN 0x100
static char line_buf[LINE_BUF_LEN];
static char name_buf[LINE_BUF_LEN];

static swiSHA1context_t ctx;

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

static const char * const cmd_strs[] = {
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
	ERR_CMD_FAIL = -2,
	ERR_CP_FAIL = -3,
	ERR_WEIRD = -4,
	ERR_SHA1_FAIL = -5
};

static int cmd_exist(const char * arg, unsigned fmt) {
	struct stat s;
	iprintf("%s", arg);
	sniprintf(name_buf, LINE_BUF_LEN, "%s%s", nand_root, arg);
	convert_backslash(name_buf);
	if (stat(name_buf, &s) == 0 && (s.st_mode & S_IFMT) == fmt) {
		iprintf(" exist\n");
		return NO_ERR;
	} else {
		iprintf(" doesn't exist\n");
		return ERR_CMD_FAIL;
	}
}

static void rm(const char *name) {
	int r = remove(name);
	if (r == 0) {
		iprintf("removed: %s\n", name);
	} else {
		iprintf("removed() returned %d for %s\n", r, name);
	}
}

static int cmd_rm(const char * arg) {
	sniprintf(name_buf, LINE_BUF_LEN, "%s%s", nand_root, arg);
	convert_backslash(name_buf);
	unsigned len = strlen(name_buf);
	if (len > 2 && name_buf[len - 1] == '*' && name_buf[len - 2] == '/') {
		// wildcard
		name_buf[len - 1] = 0;
		while (true) {
			DIR *d = opendir(name_buf);
			if (d == 0) {
				break;
			}
			struct dirent *de;
			int file_found = 0;
			while ((de = readdir(d)) != 0) {
				if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
					continue;
				}
				// BEWARE: line_buf destroyed
				// maybe I should define a secondary name_buf
				sniprintf(line_buf, LINE_BUF_LEN, "%s%s", name_buf, de->d_name);
				struct stat s;
				if (stat(line_buf, &s) != 0) {
					continue;
				}
				if ((s.st_mode & S_IFMT) == S_IFREG) {
					file_found = 1;
					rm(line_buf);
					// we break the loop here since behavior of readdir() becomes undefined in this situation
					// this is also why listdir is not used
					// http://pubs.opengroup.org/onlinepubs/007908799/xsh/readdir.html
					// QUOTE: If a file is removed from or added to the directory after the most recent call to opendir() or rewinddir(), whether a subsequent call to readdir() returns an entry for that file is unspecified.
					break;
				}
			}
			closedir(d);
			if (!file_found) {
				break;
			}
		}
	} else {
		// single file
		rm(name_buf);
	}
	// it never returns error
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

int cp(const char *from, const char *to) {
	FILE *f = fopen(from, "r");
	if (f == 0) {
		return -1;
	}
	FILE *t = fopen(to, "w");
	if (t == 0) {
		fclose(f);
		return -2;
	}
	int ret = 0;
	while (1) {
		size_t read = fread(file_buf, 1, FILE_BUF_LEN, f);
		if (read == 0) {
			break;
		}
		size_t written = fwrite(file_buf, 1, read, t);
		if (written != read) {
			ret = -3;
			break;
		}
		if (read < FILE_BUF_LEN) {
			break;
		}
	}
	fclose(f);
	fclose(t);
	return ret;
}

// this is evolved from parse_sha1sum so the structure is a bit strange
int scripting(const char *scriptname, int dry_run, unsigned *p_size){
	sniprintf(name_buf, LINE_BUF_LEN, "%s%s", list_dir, scriptname);
	FILE *f = fopen(name_buf, "r");
	unsigned irregular = 0;
	unsigned size = 0;
	unsigned missing = 0;
	unsigned wrong = 0;
	unsigned check = 0;
	int ret = 0;
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
			ret = exe_ret;
			break;
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
			iprintf("%s", name);
			// hash
			unsigned char digest[SHA1_LEN];
			if (dry_run) {
				// TODO: maybe a "files on NAND are identical" test
				int sha1_ret = sha1_file(digest, name);
				if (sha1_ret == -1) {
					iprintf(" missing\n");
					++missing;
				} else {
					size += sha1_ret;
					if (memcmp(line, digest, SHA1_LEN)) {
						iprintf(" wrong\n");
						++wrong;
					} else {
						iprintf(" OK\n");
						++check;
					}
				}
			} else {
				sniprintf(name_buf, LINE_BUF_LEN, "%s%s", nand_root, name);
				int cp_ret = cp(name, name_buf);
				if (cp_ret != 0) {
					iprintf(" failed to copy, cp() returned %d, you may panic now\n", cp_ret);
					ret = ERR_CP_FAIL;
					break;
				}
				iprintf(" copied to NAND");
				if (sha1_file(digest, name_buf) == -1) {
					iprintf(" but missing, weird\n");
					ret = ERR_WEIRD;
					break;
				} else if (memcmp(line, digest, SHA1_LEN)) {
					iprintf(" but verification failed, you may panic now\n");
					ret = ERR_SHA1_FAIL;
					break;
				} else {
					iprintf(" and verified\n");
				}
			}
		}
	}
	fclose(f);
	if (dry_run) {
		iprintf("%u/%u OK/All, %u bytes\n", check, check + missing + wrong, size);
		if (missing + wrong > 0) {
			iprintf("%u wrong, %u missing\n", wrong, missing);
		}
		if (irregular > 0) {
			iprintf("%u irregular lines\n", irregular);
		}
		*p_size = size;
		return ret != 0 ? ret : irregular + missing + wrong;
	} else {
		return ret;
	}
}

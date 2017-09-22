
// a POSIX directory tree walk
// walk down subdirectories and calls callback on regular files, skip all others

#include <malloc.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include "walk.h"

#define NAME_BUF_LEN 0x100
static char name_buf[NAME_BUF_LEN];

#define STACK_DEPTH 0x400

static void **base;
static unsigned head;

static unsigned stack_usage;
static unsigned stack_max_depth;

// I suppose no need for a linked stack
static void s_alloc() {
	base = memalign(sizeof(void*), sizeof(void*) * STACK_DEPTH);
	head = 0;
}

static void s_free() {
	free(base);
}

static int s_push(void *p) {
	++stack_usage;
	if (head < STACK_DEPTH) {
		base[head++] = p;
		if (head > stack_max_depth) {
			stack_max_depth = head;
		}
		return 1;
	} else {
		iprintf("stack limit exceed\n");
		return 0;
	}
}

static void* s_pop() {
	if (head > 0) {
		return base[--head];
	} else {
		return 0;
	}
}

static void s_deep_free() {
	void *p;
	while ((p = s_pop()) != 0) {
		free(p);
	}
	free(base);
}

int walk(const char *dir, void (*callback)(const char*, void*), void *p_cb_param) {
	// init the stack
	stack_max_depth = 0;
	stack_usage = 0;
	s_alloc();
	char *p = (char*)malloc(strlen(dir) + 1);
	if (p == 0) {
		return -1;
	}
	strcpy(p, dir);
	s_push(p);
	// walk the stack
	while ((p = (char*)s_pop()) != 0) {
		size_t len_parent = strlen(p);
		DIR * d = opendir(p);
		if (d == 0) {
			free(p);
			continue;
		}
		struct dirent * de;
		while ((de = readdir(d)) != 0) {
			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
				continue;
			}
			char *fullname = (char*)malloc(len_parent + 1 + strlen(de->d_name) + 1);
			if (fullname == 0) {
				s_deep_free();
				return -1;
			}
			siprintf(fullname, p[strlen(p) - 1] == '/' ? "%s%s" : "%s/%s", p, de->d_name);
			struct stat s;
			if (stat(fullname, &s) != 0) {
				free(fullname);
				continue;
			}
			if (s.st_mode & S_IFREG) {
				callback(fullname, p_cb_param);
				free(fullname);
			} else if (s.st_mode & S_IFDIR) {
				if (s_push(fullname) == 0) {
					free(fullname);
					s_deep_free();
					return -2;
				}
			} else {
				free(fullname);
			}
		}
		closedir(d);
		free(p);
	}
	s_free();
	iprintf("stack stats: %u/%u\n", stack_max_depth, stack_usage);
	return 0;
}

void listdir(const char *dir, int want_full, void(*callback)(const char*, size_t, void*), void *p_cb_param) {
	DIR * d = opendir(dir);
	if (d == 0) {
		return;
	}
	struct dirent * de;
	while ((de = readdir(d)) != 0) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
			continue;
		}
		sniprintf(name_buf, NAME_BUF_LEN, dir[strlen(dir) - 1] == '/' ? "%s%s" : "%s/%s", dir, de->d_name);
		struct stat s;
		if (stat(name_buf, &s) != 0) {
			continue;
		}
		if ((s.st_mode & S_IFMT) == S_IFREG) {
			callback(want_full ? name_buf : de->d_name, s.st_size, p_cb_param);
		} else if ((s.st_mode & S_IFMT) == S_IFDIR) {
			// use INVALID_SIZE as indication
			callback(want_full ? name_buf : de->d_name, INVALID_SIZE, p_cb_param);
		}
	}
	closedir(d);
}

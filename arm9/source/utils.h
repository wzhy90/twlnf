
#pragma once

#include <nds.h>
#include "common.h"

int hex2bytes(u8 *out, unsigned byte_len, const char *in);

const char * to_mebi(size_t size);

int save_file(const char *filename, u8 *buffer, size_t size, int save_sha1);

int load_file(void **pbuf, size_t *psize, const char *filename, int verify_sha1, int align);

int save_sha1_file(const char *filename, swiSHA1context_t *ctx);

void print_bytes(const void *buf, size_t len);

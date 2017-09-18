
#pragma once

#include "common.h"

int hexToBytes(u8 *out, unsigned byte_len, const char *in);

const char * toMebi(size_t size);

int saveToFile(const char *filename, u8 *buffer, size_t size, bool saveSHA1);

int loadFromFile(void **pbuf, size_t *psize, const char *filename, bool verifySHA1, int align);

int saveSHA1File(const char *filename);

void printBytes(const void *buf, size_t len);

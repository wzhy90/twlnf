#pragma once

int sumfile_parser(const char *filename, unsigned hashlen,
	void(*callback)(const char*, const unsigned char*, void*), void *p_cb_param);

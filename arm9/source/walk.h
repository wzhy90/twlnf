#pragma once

int walk(const char *dir, void(*callback)(const char*, void*), void *p_cb_param);

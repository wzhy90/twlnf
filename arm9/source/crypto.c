
#include <nds.h>
#include <stdio.h>
#include "aes.h"
#include "crypto.h"
#include "utils.h"

// more info:
//		https://github.com/Jimmy-Z/TWLbf/blob/master/dsi.c
//		https://github.com/Jimmy-Z/bfCL/blob/master/dsi.h
// ported back to 32 bit for ARM9

static const u32 DSi_KEY_Y[4] =
	{0x0ab9dc76u, 0xbd4dc4d3u, 0x202ddd1du, 0xe1a00005u};

static const u32 DSi_KEY_MAGIC[4] =
	{0x1a4f3e79u, 0x2a680f5fu, 0x29590258u, 0xfffefb4eu};

static inline u32 u32be(const u8 *in){
	u32 out;
	u8 *out8 = (u8*)&out;
	out8[0] = in[3];
	out8[1] = in[2];
	out8[2] = in[1];
	out8[3] = in[0];
	return out;
}

static inline void byte_reverse_16(u8 *o, const u8 *i) {
	o[0] = i[15];
	o[1] = i[14];
	o[2] = i[13];
	o[3] = i[12];
	o[4] = i[11];
	o[5] = i[10];
	o[6] = i[9];
	o[7] = i[8];
	o[8] = i[7];
	o[9] = i[6];
	o[10] = i[5];
	o[11] = i[4];
	o[12] = i[3];
	o[13] = i[2];
	o[14] = i[1];
	o[15] = i[0];
}

// in place
static inline void byte_reverse_16_ip(u8 *io){
	u8 t;
#define SWAP(a, b) t = io[a]; io[a] = io[b]; io[b] = t
	SWAP(0, 15);
	SWAP(1, 14);
	SWAP(2, 13);
	SWAP(3, 12);
	SWAP(4, 11);
	SWAP(5, 10);
	SWAP(6, 9);
	SWAP(7, 8);
#undef SWAP
}

static inline void xor_128(u32 *x, const u32 *a, const u32 *b){
	x[0] = a[0] ^ b[0];
	x[1] = a[1] ^ b[1];
	x[2] = a[2] ^ b[2];
	x[3] = a[3] ^ b[3];
}

static inline void add_128(u32 *a, const u32 *b){
	unsigned c1, c2, c3; // carry
	// round 1
	a[3] += b[3];
	a[2] += b[2];
	a[1] += b[1];
	a[0] += b[0];
	// carry
	c3 = a[2] < b[2];
	c2 = a[1] < b[1];
	c1 = a[0] < b[0];
	// round 2
	a[3] += c3;
	a[2] += c2;
	a[1] += c1;
	// carry
	c3 = a[2] < c2;
	c2 = a[1] < c1;
	// round 3
	a[3] += c3;
	a[2] += c2;
	// carry
	c3 = a[2] < c2;
	// round 4
	a[3] += c3;
}

static inline void add_128_32(u32 *a, u32 b){
	a[0] += b;
	if(a[0] < b){
		a[1] += 1;
		if (a[1] == 0) {
			a[2] += 1;
			if (a[2] == 0) {
				a[3] += 1;
			}
		}
	}
}

// Answer to life, universe and everything.
static inline void rol42_128(u32 *a){
	// ROL 32
	u32 t[4] = { a[3], a[0], a[1], a[2] };
	// ROL 10
	a[0] = (t[0] << 10) | (t[3] >> 22);
	a[1] = (t[1] << 10) | (t[0] >> 22);
	a[2] = (t[2] << 10) | (t[1] >> 22);
	a[3] = (t[3] << 10) | (t[2] >> 22);
}

// eMMC Encryption for MBR/Partitions (AES-CTR, with console-specific key)
static void dsi_make_key(u32 *key, u32 console_id_l, u32 console_id_h, int is3DS){
	if (is3DS) {
		key[0] = (console_id_l ^ 0xb358a6af) | 0x80000000;
		key[1] = 0x544e494e;
		key[2] = 0x4f444e45;
		key[3] = console_id_h ^ 0x08c267b7;
	} else {
		key[0] = console_id_l;
		key[1] = console_id_l ^ 0x24ee6906;
		key[2] = console_id_h ^ 0xe65b601d;
		key[3] = console_id_h;
	}
	// iprintf("AES KEY_X:\n");
	// print_bytes(key, 16);
	// Key = ((Key_X XOR Key_Y) + FFFEFB4E295902582A680F5F1A4F3E79h) ROL 42
	// equivalent to F_XY in twltool/f_xy.c
	xor_128(key, key, DSi_KEY_Y);
	// iprintf("AES KEY: XOR KEY_Y:\n");
	// print_bytes(key, 16);
	add_128(key, DSi_KEY_MAGIC);
	// iprintf("AES KEY: + MAGIC:\n");
	// print_bytes(key, 16);
	rol42_128(key);
	// iprintf("AES KEY: ROL 42:\n");
	// print_bytes(key, 16);
	byte_reverse_16_ip((u8*)key);
}

static u32 rk[RK_LEN];
static u32 ctr_base[4];

int tables_generated = 0;

void dsi_nand_crypt_init(const u8 *console_id, const u8 *emmc_cid, int is3DS) {
	if (tables_generated == 0) {
		aes_gen_tables();
		tables_generated = 1;
	}

	u32 key[4];
	u32 console_id_l = u32be(console_id + 4);
	u32 console_id_h = u32be(console_id);
	dsi_make_key(key, console_id_l, console_id_h, is3DS);
	// iprintf("AES KEY:\n");
	// print_bytes(key, 16);
	aes_set_key_enc_128(rk, (u8*)key);

	u32 digest[5];
	swiSHA1context_t ctx;
	ctx.sha_block = 0;
	swiSHA1Init(&ctx);
	swiSHA1Update(&ctx, emmc_cid, 16);
	swiSHA1Final(digest, &ctx);
	ctr_base[0] = digest[0];
	ctr_base[1] = digest[1];
	ctr_base[2] = digest[2];
	ctr_base[3] = digest[3];
}

// crypt one AES block, in/out must be aligned to 32 bits
// offset as block offset
void dsi_nand_crypt_1(u8* out, const u8* in, u32 offset) {
	u32 buf[4] = { ctr_base[0], ctr_base[1], ctr_base[2], ctr_base[3] };
	add_128_32(buf, offset);
	byte_reverse_16_ip((u8*)buf);
	// iprintf("AES CTR:\n");
	// print_bytes(buf, 16);
	aes_encrypt_128(rk, (u8*)buf, (u8*)buf);
	byte_reverse_16_ip((u8*)buf);
	xor_128((u32*)out, (u32*)in, buf);
}

void dsi_nand_crypt(u8* out, const u8* in, u32 offset, unsigned count) {
	for (unsigned i = 0; i < count; ++i) {
		dsi_nand_crypt_1(out + i * AES_BLOCK_SIZE, in + i * AES_BLOCK_SIZE, offset + i);
	}
}
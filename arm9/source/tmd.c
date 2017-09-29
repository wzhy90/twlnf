#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "../term256/term256ext.h"
#include "../mbedtls/rsa.h"
#include "../mbedtls/aes.h"
#include "heap.h"
#include "utils.h"
#include "walk.h"
#include "ticket0.h"
#include "crypto.h"

extern const char nand_root[];

const char cert_sys_path[] = "sys/cert.sys";
const char cert_cp07_name[] = "CP00000007";
const char dsiware_ticket_path[] = "ticket/00030004/";

const u32 dsiware_title_id_h = 0x00030004;

rsa_context_t rsa_cp07;

unsigned char * ticket_template;

int setup_cp07_pubkey() {
	cert_t *cert = malloc(sizeof(cert_t));
	if (cert == 0){
		prt("failed to alloc memory\n");
		return -1;
	}
	int ret;
	char *cert_full_path = alloc_buf();
	strcpy(cert_full_path, nand_root);
	strcat(cert_full_path, cert_sys_path);
	if (load_block_from_file(cert, cert_full_path, 0x700, sizeof(cert_t)) != 0) {
		iprtf("failed to load cert from %s\n", cert_sys_path);
		ret = -1;
	} else {
		if (strncmp(cert->key_name, cert_cp07_name, sizeof(cert_cp07_name)) != 0) {
			iprtf("unexpected key name %s, should be %s\n", cert->key_name, cert_cp07_name);
			ret = -2;
		} else {
			rsa_init(&rsa_cp07);
			if (rsa_set_pubkey(&rsa_cp07,
				cert->rsa_key, sizeof(cert->rsa_key),
				cert->rsa_exp, sizeof(cert->rsa_exp)) != 0) {
				prt("failed to setup RSA key\n");
				ret = -1;
			} else {
				ret = 0;
			}
		}
	}
	free(cert);
	free_buf(cert_full_path);
	return ret;
}

// returns 0 on success, and write SHA1 to out
int decrypt_cp07_signature(unsigned char *out, const unsigned char *in) {
	static_assert(RSA_2048_LEN <= BUF_SIZE, "BUF_SIZE shouldn't < RSA_2048_LEN");
	unsigned char *sig = (unsigned char*)alloc_buf();
	int ret;
	if (sig == 0) {
		prt("failed to alloc memory\n");
		ret = -1;
	} else if (rsa_public(&rsa_cp07, in, sig) != 0){
		prt("failed to decrypt signature\n");
		ret = -2;
	} else if (sig[0] != 0 || out[1] != 1 || out[2] != 0xff
		|| sig[RSA_2048_LEN - 0x14 - 1] != 0x14) {
		prt("invalid signature\n");
		ret = -3;
	} else {
		memcpy(out, sig + RSA_2048_LEN - 0x14, 0x14);
		ret = 0;
	}
	free_buf(sig);
	return ret;
}

#define TICKET_SIZE (sizeof(ticket_v0_t) + sizeof(es_block_footer_t))
#define TICKET_ALIGN 4
static_assert(TICKET_SIZE % TICKET_ALIGN == 0, "invalid TICKET_ALIGN");

unsigned wait_keys(unsigned);

static int find_ticket_cb(const char* filename, size_t size, void *cb_param) {
	if (size == INVALID_SIZE || size < TICKET_SIZE) {
		return 0;
	}
	if (load_block_from_file(ticket_template, filename, 0, TICKET_SIZE) != 0) {
		iprtf("failed to load ticket: %s\n", filename);
		// return 0 to let list_dir continue
		return 0;
	}
	if (dsi_es_block_crypt(ticket_template, TICKET_SIZE, DECRYPT) != 0) {
		iprtf("failed to decrypt ticket: %s\n", filename);
		return 0;
	}
	ticket_v0_t *ticket = (ticket_v0_t*)ticket_template;
	// maybe we should reject XS00000006 tickets, only allow XS00000003?
	// iprtf("ticket signature issuer: %s\n", ticket->issuer);
	// TODO: maybe also validate ticket signature
	u32 title_id[2];
	GET_UINT32_BE(title_id[0], ticket->title_id, 4);
	GET_UINT32_BE(title_id[1], ticket->title_id, 0);
	if (title_id[1] != dsiware_title_id_h) {
		iprtf("weird, got a %08lx ticket\n", title_id[1]);
		return 0;
	}
	*(int*)cb_param = 1;
	return 1;
}

int setup_ticket_template() {
	char * ticket_path = alloc_buf();
	strcpy(ticket_path, nand_root);
	// strcpy(ticket_path, "sd:/twlnf/dump/");
	strcat(ticket_path, dsiware_ticket_path);
	// we'll do AES on that, so must be aligned at least 32 bit
	ticket_template = memalign(TICKET_ALIGN, TICKET_SIZE);
	if (ticket_template == 0) {
		prt("failed to alloc memory\n");
		free_buf(ticket_path);
		return -1;
	}
	// iprtf("ticket_template addr: %08x\n", (unsigned)ticket_template);
	int found = 0;
	list_dir(ticket_path, 1, find_ticket_cb, &found);
	free_buf(ticket_path);
	if (found) {
		return 0;
	} else {
		free(ticket_template);
		ticket_template = 0;
		return 1;
	}
}

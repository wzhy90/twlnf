#include <stdio.h>
#include <string.h>
#include "../term256/term256ext.h"
#include "../mbedtls/rsa.h"
#include "heap.h"
#include "utils.h"
#include "walk.h"
#include "ticket0.h"

rsa_context_t rsa_cp07;

extern const char nand_root[];

const char cert_sys_path[] = "sys/cert.sys";
const char cert_cp07_name[] = "CP00000007";
const char dsiware_ticket_path[] = "ticket/00030004/";

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

static int find_ticket_cb(const char* filename, size_t size, void *cb_param) {
	if (size == sizeof(ticket_v0_t)) {
		return 1;
	}
	return 0;
}

int setup_ticket_template() {
	prt("not implemented\n");
	list_dir(0, 1, find_ticket_cb, 0);
	return 0;
}
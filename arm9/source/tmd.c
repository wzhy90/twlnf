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
#include "scripting.h"

extern const char nand_root[];

const char cert_sys_fullname[] = "sys/cert.sys";
const char cert_cp07_name[] = "CP00000007";
const uint32_t dsiware_title_id_h = 0x00030004;

// used while looking for a ticket template
const char ticket_dir_fmt[] = "%sticket/%08lx/";
// used while reading app aside tmd on SD
const char app_src_fmt[] = "%s%08lx.app";
// dst full name generation
const char ticket_fullname_fmt[] = "%sticket/%08lx/%08lx.tik";
const char tmd_fullname_fmt[] = "%stitle/%08lx/%08lx/content/tmd";
const char app_fullname_fmt[] = "%stitle/%08lx/%08lx/content/%08lx.app";

rsa_context_t rsa_cp07;

uint8_t * ticket_template;

int setup_cp07_pubkey() {
	cert_t *cert = malloc(sizeof(cert_t));
	if (cert == 0){
		prt("failed to alloc memory\n");
		return -1;
	}
	int ret;
	char *cert_full_path = alloc_buf();
	strcpy(cert_full_path, nand_root);
	strcat(cert_full_path, cert_sys_fullname);
	if (load_block_from_file(cert, cert_full_path, 0x700, sizeof(cert_t)) != 0) {
		iprtf("failed to load cert from %s\n", cert_sys_fullname);
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
int decrypt_cp07_signature(uint8_t *out, const uint8_t *in) {
	static_assert(RSA_2048_LEN <= BUF_SIZE, "BUF_SIZE shouldn't < RSA_2048_LEN");
	uint8_t *sig = (uint8_t*)alloc_buf();
	int ret;
	if (sig == 0) {
		prt("failed to alloc memory\n");
		ret = -1;
	} else if (rsa_public(&rsa_cp07, in, sig) != 0){
		prt("failed to decrypt signature\n");
		ret = -2;
	} else if (sig[0] != 0 || sig[1] != 1 || sig[2] != 0xff
		|| sig[RSA_2048_LEN - SHA1_LEN - 1] != SHA1_LEN) {
		prt("invalid signature, first 16 bytes:\n\t");
		print_bytes(sig, 16);
		prt("\nlast 32 bytes:\n\t");
		print_bytes(sig + RSA_2048_LEN - 32, 16);
		prt("\n\t");
		print_bytes(sig + RSA_2048_LEN - 16, 16);
		prt("\n");
		ret = -3;
	} else {
		memcpy(out, sig + RSA_2048_LEN - SHA1_LEN, SHA1_LEN);
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
#define ES_ENCRYPT_TEST 1
#if ES_ENCRYPT_TEST
	uint8_t *ticket_original = memalign(TICKET_ALIGN, TICKET_SIZE);
	assert(ticket_original != 0);
	memcpy(ticket_original, ticket_template, TICKET_SIZE);
#endif
	if (dsi_es_block_crypt(ticket_template, TICKET_SIZE, DECRYPT) != 0) {
		iprtf("failed to decrypt ticket: %s\n", filename);
		return 0;
	}
#if ES_ENCRYPT_TEST
	uint8_t *ticket_enc = memalign(TICKET_ALIGN, TICKET_SIZE);
	assert(ticket_enc != 0);
	memcpy(ticket_enc, ticket_template, TICKET_SIZE);
	assert(dsi_es_block_crypt(ticket_enc, TICKET_SIZE, ENCRYPT) == 0);
	if (memcmp(ticket_original, ticket_enc, TICKET_SIZE) == 0) {
		prtf("ES encryption test OK\n");
	} else {
		prtf("ES encryption test failed\n");
	}
	free(ticket_original);
	free(ticket_enc);
#endif
	ticket_v0_t *ticket = (ticket_v0_t*)ticket_template;
	// maybe we should reject XS00000006 tickets, only allow XS00000003?
	// iprtf("ticket signature issuer: %s\n", ticket->issuer);
	// TODO: maybe also validate ticket signature
	uint32_t title_id[2];
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
	// we'll do AES-CCM on that, so must be aligned at least 32 bit
	ticket_template = memalign(TICKET_ALIGN, TICKET_SIZE);
	if (ticket_template == 0) {
		prt("failed to alloc memory\n");
		return -1;
	}
	// iprtf("ticket_template addr: %08x\n", (unsigned)ticket_template);
	char * ticket_dir = alloc_buf();
	sprintf(ticket_dir, ticket_dir_fmt, nand_root, dsiware_title_id_h);
	int found = 0;
	list_dir(ticket_dir, 1, find_ticket_cb, &found);
	free_buf(ticket_dir);
	if (found) {
		return 0;
	} else {
		free(ticket_template);
		ticket_template = 0;
		return 1;
	}
}

#define TMD_SIZE (sizeof(tmd_header_v0_t) + sizeof(tmd_content_v0_t))

int tmd_verify(const uint8_t *tmd_buf, const char *tmd_dir, char *tmd_dst_fullname,
	char *app_src_fullname, uint8_t *app_sha1, int *psize, char *app_dst_fullname,
	uint8_t *ticket_buf, char *ticket_dst_fullname)
{
	tmd_header_v0_t *header = (tmd_header_v0_t*)tmd_buf;
	uint32_t title_id[2];
	GET_UINT32_BE(title_id[0], header->title_id, 4);
	GET_UINT32_BE(title_id[1], header->title_id, 0);
	if (title_id[1] != dsiware_title_id_h) {
		iprtf("not a DSiWare title(%08lx)\n", title_id[1]);
		return -1;
	}
	iprtf("Title ID: %08lx/%c%c%c%c\n", title_id[1],
		header->title_id[4], header->title_id[5], header->title_id[6], header->title_id[7]);
	if (header->num_content[0] != 0 || header->num_content[1] != 1) {
		iprtf("num_content should be 1(%02x%02x)\n",
			header->num_content[0], header->num_content[1]);
		return -1;
	}
	// I'm ashamed to used app_sha1 for a different thing 
	if (decrypt_cp07_signature(app_sha1, header->sig) != 0) {
		return -1;
	}
#define SIG_OFFSET (sizeof(header->sig_type) + sizeof(header->sig) + sizeof(header->padding0))
#define SIG_LEN (TMD_SIZE - SIG_OFFSET)
	if (dsi_sha1_verify(app_sha1, tmd_buf + SIG_OFFSET, SIG_LEN) != 0) {
#undef SIG_OFFSET
#undef SIG_LEN
		prt("TMD signature verification failed\n");
		return -1;
	} else {
		prt("TMD signature verified\n");
	}
	// verify app
	tmd_content_v0_t *content = (tmd_content_v0_t*)(tmd_buf + sizeof(tmd_header_v0_t));
	uint32_t content_id;
	GET_UINT32_BE(content_id, content->content_id, 0);
	sprintf(app_src_fullname, app_src_fmt, tmd_dir, content_id);
	prt(app_src_fullname);
	if ((*psize = sha1_file(app_sha1, app_src_fullname)) == -1) {
		prt(" <- couldn't open\n");
		return -1;
	}
	if (memcmp(content->sha1, app_sha1, SHA1_LEN) != 0) {
		prt(" SHA1 doesn't match\n");
		return -1;
	} else {
		prt(" SHA1 verified\n");
	}
	// forge ticket
	memcpy(ticket_buf, ticket_template, TICKET_SIZE);
	ticket_v0_t *ticket = (ticket_v0_t*)ticket_buf;
	PUT_UINT32_BE(title_id[0], ticket->title_id, 4);
	if (dsi_es_block_crypt(ticket_buf, TICKET_SIZE, ENCRYPT) != 0) {
		prt("weird, failed to forge ticket\n");
		return -1;
	}
	// generate paths
	sprintf(ticket_dst_fullname, ticket_fullname_fmt, nand_root, title_id[1], title_id[0]);
	sprintf(tmd_dst_fullname, tmd_fullname_fmt, nand_root, title_id[1], title_id[0]);
	sprintf(app_dst_fullname, app_fullname_fmt, nand_root, title_id[1], title_id[0], content_id);
	return 0;
}

int wait_yes_no(const char *);

void verify(const char *fullname, const uint8_t *digest_verify) {
	uint8_t digest[SHA1_LEN];
	int ret = sha1_file(digest, fullname);
	if (ret == -1) {
		prt(" but failed to read for verification\n");
	} else if (memcmp(digest, digest_verify, SHA1_LEN)) {
		prt(" but verification failed\n");
	} else {
		prt(" and verified\n");
	}
}

void save_and_verify(const char *fullname, uint8_t *buf, size_t len) {
	prt(fullname);
	int ret = save_file(fullname, buf, len, 0);
	if (ret != 0) {
		prt(" failed to write\n");
	} else {
		prt(" written to NAND");
		uint8_t digest[SHA1_LEN];
		dsi_sha1_verify(digest, buf, len);
		verify(fullname, digest);
	}
}

void install_tmd(const char *tmd_fullname, const char *tmd_dir, int max_size) {
	// TMD file
	uint8_t *tmd_buf = malloc(TMD_SIZE);
	if (tmd_buf == 0) {
		prt("failed to alloc memory for TMD\n");
		return;
	}
	uint8_t *ticket_buf = memalign(TICKET_ALIGN, TICKET_SIZE);
	if (ticket_buf == 0) {
		prt("failed to alloc memory for ticket\n");
		free(tmd_buf);
		return;
	}
	if (load_block_from_file(tmd_buf, tmd_fullname, 0,
		sizeof(tmd_header_v0_t) + sizeof(tmd_content_v0_t)) != 0) {
		prt("failed to load TMD\n");
		free(tmd_buf);
		free(ticket_buf);
		return;
	}
	char *tmd_dst_fullname = alloc_buf();
	char *app_src_fullname = alloc_buf();
	uint8_t app_sha1[SHA1_LEN];
	int size;
	char *app_dst_fullname = alloc_buf();
	char *ticket_dst_fullname = alloc_buf();
	if (tmd_verify(tmd_buf, tmd_dir, tmd_dst_fullname,
		app_src_fullname, app_sha1, &size, app_dst_fullname,
		ticket_buf, ticket_dst_fullname) == 0) {
		if (size > max_size) {
			prt("insufficient NAND space\n");
		} else if(wait_yes_no("install to NAND?")){
			// write ticket
			FILE *f = fopen(ticket_dst_fullname, "r");
			if (f != 0) {
				fclose(f);
				prt("ticket already exist, won't overwrite\n");
			} else {
				save_and_verify(ticket_dst_fullname, ticket_buf, TICKET_SIZE);
			}
			// write TMD
			save_and_verify(ticket_dst_fullname, ticket_buf, TICKET_SIZE);
			// write app
			prt(app_dst_fullname);
			if (cp(app_src_fullname, app_dst_fullname) != 0) {
				prt(" failed to copy\n");
			} else {
				prt(" copied to NAND");
				verify(app_dst_fullname, app_sha1);
			}
		}
	}
	free(tmd_buf);
	free(ticket_buf);
	free_buf(tmd_dst_fullname);
	free_buf(app_src_fullname);
	free_buf(app_dst_fullname);
	free_buf(ticket_dst_fullname);
}

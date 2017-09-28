
#define MBEDTLS_ERR_RSA_PUBLIC_FAILED                     -0x4280  /**< The public key operation failed. */

void rsa_init();

void rsa_set_pubkey(const unsigned char * n_buf, size_t n_len,
	const unsigned char * e_buf, size_t e_len);

int rsa_public(const unsigned char *input, unsigned char *output);

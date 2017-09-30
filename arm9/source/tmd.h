
int setup_cp07_pubkey();

int decrypt_cp07_signature(unsigned char *out, const unsigned char *in);

int setup_ticket_template();

void install_tmd(const char *tmd_fullname, const char *tmd_dir, int max_size);

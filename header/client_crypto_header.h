/*
	Header file for client_crypto_helper.c
*/
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// structure to hold an encrypted block
struct enc_block {
	// actual ciphertext
	unsigned char * ciphertext;
	// ciphertext length
	char * ciphertext_len;
};

// structure for TGT (ticket granting ticket)
struct TGT {
	// actual ciphertext
	unsigned char * ciphertext;
	// cipehertext length
	char * ciphertext_len;
};

// initializer function to encrypt client's password and timestamp
struct enc_block * initialize_crypto(char*, char*);
// generate SHA256 hash of the password
void generate_SHA256_digest(const unsigned char *, size_t, unsigned char **, unsigned int *);
// initializer function to decrypt the encrypted block sent by the client
int decrypt_initializer(char*, unsigned char*, int, unsigned char*, unsigned char*);
struct enc_block * encrypt_message_initializer (unsigned char *, char *);
int decrypt_msg_initializer (unsigned char *, unsigned char *, int, unsigned char *, unsigned char *);
void copy_to_unsigned_char_array(unsigned char *, unsigned char *, unsigned char *, int, int);
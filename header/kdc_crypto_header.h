/*
	Header file for kdc_crypto_helper.c
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
	// length of ciphertext
	char * ciphertext_len;
};

// initializer function to decrypt the encrypted block sent by the client
int decrypt_initializer(char*, unsigned char*, int, unsigned char*, unsigned char*);
// initializer function to generate TGT by KDC for the client
struct TGT * create_tgt(char*);
// generate SHA256 hash of the password
void generate_SHA256_digest(const unsigned char *, size_t, unsigned char **, unsigned int *);
// generate 256 bit key
void generate_key(unsigned char*);
struct enc_block * encrypt_session_key_initializer(char *, unsigned char *, long long int);
struct enc_block * encrypt_ticket_initializer(char *, char *, unsigned char *, long long int);
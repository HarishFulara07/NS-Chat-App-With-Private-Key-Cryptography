#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

typedef unsigned char byte;
#define UNUSED(x) ((void)x)

/* Returns 0 for success, non-0 otherwise */
int make_keys(EVP_PKEY**, unsigned char *);

/* Returns 0 for success, non-0 otherwise */
int sign_it(const byte*, size_t, byte**, size_t*, EVP_PKEY*);

/* Returns 0 for success, non-0 otherwise */
int verify_it(const byte*, size_t, const byte*, size_t, EVP_PKEY*);

int sign_msg_using_hmac(char *, unsigned char *, unsigned char *);
int verify_msg_using_hmac(unsigned char*, size_t, unsigned char*, size_t,unsigned char *);
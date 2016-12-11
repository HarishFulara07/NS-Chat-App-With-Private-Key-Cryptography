#include "../header/common_header.h"
#include "../header/client_header.h"
#include "../header/client_crypto_header.h"

// helper function to handle any errors
// This will simply dump any error messages from the OpenSSL error stack to the screen,
// and then abort the program.
void handleErrors() {
	ERR_print_errors_fp(stderr);
	abort();
}

// get length of a long value
int get_length(long long int val) {
	int len = 0;

	while(val > 0) {
		len++;
		val = val/10;
	}

	return len;
}

// converts long to string
void long_to_str(long long val, int len, unsigned char * str) {
	int num[len];
	int tmp = val;
	int pos = 0;

	while(tmp > 0) {
		int rem = tmp % 10;
		num[pos] = rem;
		pos++;
		tmp = tmp / 10;
	}

	while(pos > 0) {
		pos--;
		str[len-pos-1] = num[pos] + '0';
	}
}

void copy_to_unsigned_char_array(unsigned char * target, unsigned char * src1, unsigned char * src2, int len1, int len2) {

	int i, j = 0;

	for (i = 0; i < len1; ++i) {
		target[j] = src1[i];
		++j;
	}

	target[j] = ':';
	++j;

	for (i = 0; i < len2; ++i) {
		target[j] = src2[i];
		++j;
	}
}


// generate SHA256 hash of the password
void generate_SHA256_digest(const unsigned char *message, size_t message_len,
						unsigned char **digest, unsigned int *digest_len) {
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_create()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors();

	EVP_MD_CTX_destroy(mdctx);
}

// encrypts the plaintext using AES256
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext) {
	// Setting up the context for encryption
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	// Create and initialise the context
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		handleErrors();
	}

	// Initialise the encryption operation.
	// In this example we are using 256 bit AES (i.e. a 256 bit key). The
	// IV size for *most* modes is the same as the block size. For AES this
	// is 128 bits
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))	{
		handleErrors();
	}

	// Provide the message to be encrypted, and obtain the encrypted output.
	// EVP_EncryptUpdate can be called multiple times if necessary
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
		handleErrors();
	}

	ciphertext_len = len;

	// Finalise the encryption. Further ciphertext bytes may be written at this stage.
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		handleErrors();
	}

	ciphertext_len += len;

	// Clean up
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext) {
	// Setting up the context for decryption 
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	// Create and initialise the context
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	// Initialise the decryption operation.
	// In this example we are using 256 bit AES (i.e. a 256 bit key). The
	// IV size for *most* modes is the same as the block size. For AES this is 128 bits 
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		handleErrors();
	}

	// Provide the message to be decrypted, and obtain the plaintext output.
	// EVP_DecryptUpdate can be called multiple times if necessary
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
		handleErrors();
	}

	plaintext_len = len;

	// Finalise the decryption. Further plaintext bytes may be written at this stage.
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
		handleErrors();
	}
	
	plaintext_len += len;

	// Clean up
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

struct enc_block * initialize_crypto (char * username, char * password) {
	// Set up the key and IV.
	// IV is NULL.

	// A 256 bit key
	unsigned char *key = (unsigned char *)malloc((32) * sizeof(unsigned char));
	
	// Generate key from passphrase
	if (1 != PKCS5_PBKDF2_HMAC((const char *)password, strlen(password), NULL, 0, 1000, EVP_sha256(), 32, key)) {
		handleErrors();
	}

	// structure to hold time passed since epoch (January 1, 1970)
	struct timeval tv;
	// get current time
	gettimeofday(&tv, NULL);

	// get the length of timestamp
	int timestamp_len = get_length((unsigned long long int)tv.tv_sec);
	unsigned char * timestamp = (unsigned char *)malloc((timestamp_len) * sizeof(unsigned char));

	// get the timestamp, i.e, time passed since epoch (January 1, 1970)
	long_to_str((unsigned long long int)tv.tv_sec, timestamp_len, timestamp);

	unsigned char plaintext[100];

	// if client wants to encrypt the block containing 
	// request to get a key for chatting with another user
	if(username != NULL) {
		// Message (username + timestamp) to be encrypted
		
		// username of the user whom we want to chat with
		copy_to_unsigned_char_array(plaintext, (unsigned char *)username, timestamp, strlen(username), timestamp_len);
	}
	// if client wants to encrypt the block containing
	// request to log into the chat server
	else {
		// Message (password + timestamp) to be encrypted
		copy_to_unsigned_char_array(plaintext, (unsigned char *)password, timestamp, strlen(password), timestamp_len);
	}

	// Buffer for ciphertext. Ensure the buffer is long enough for the
	// ciphertext which may be longer than the plaintext, dependant on the
	// algorithm and mode.
	unsigned char ciphertext[1024];

	int ciphertext_len;

	// Initialise the library
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	// Encrypt the plaintext
	ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, NULL, ciphertext);

	// inserting the values into the structure that holds encrypted login block
	struct enc_block *eb = (struct enc_block *)malloc(sizeof(struct enc_block));
	eb->ciphertext = (unsigned char *)malloc((1024) * sizeof(unsigned char));
	eb->ciphertext_len = (char *)malloc(5 * sizeof(char));
	memcpy(eb->ciphertext, ciphertext, ciphertext_len);
	strcpy(eb->ciphertext_len, int_to_str(ciphertext_len));
	
	// Clean up
	EVP_cleanup();
	ERR_free_strings();

	return eb;
}

// initializer function to decrypt the encrypted block sent by the client
int decrypt_initializer (char * password, unsigned char * ciphertext, int ciphertext_len,
	unsigned char * iv, unsigned char * decryptedtext) {
	// printf("Hello\n");
	// Set up the key and IV.

	// A 256 bit key
	unsigned char *key = (unsigned char *)malloc((32) * sizeof(unsigned char));

	// Generate key from passphrase
	if (1 != PKCS5_PBKDF2_HMAC(password, strlen(password), NULL, 0, 1000, EVP_sha256(), 32, key)) {
		handleErrors();
	}

	// Initialise the library
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	// Decrypt the ciphertext
	int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
	
	// Clean up
	EVP_cleanup();
	ERR_free_strings();

	return decryptedtext_len;
}

struct enc_block * encrypt_message_initializer (unsigned char * key, char * msg) {
	// Buffer for ciphertext. Ensure the buffer is long enough for the
	// ciphertext which may be longer than the plaintext, dependant on the
	// algorithm and mode.
	unsigned char ciphertext[1024];

	int ciphertext_len;

	// Initialise the library
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	// Encrypt the plaintext
	ciphertext_len = encrypt ((unsigned char *)msg, strlen (msg), key, NULL, ciphertext);

	// inserting the values into the structure that holds encrypted login block
	struct enc_block *eb = (struct enc_block *)malloc(sizeof(struct enc_block));
	eb->ciphertext = (unsigned char *)malloc((1024) * sizeof(unsigned char));
	eb->ciphertext_len = (char *)malloc(5 * sizeof(char));
	memcpy(eb->ciphertext, ciphertext, ciphertext_len);
	strcpy(eb->ciphertext_len, int_to_str(ciphertext_len));
	
	// Clean up
	EVP_cleanup();
	ERR_free_strings();

	return eb;
}

// initializer function to decrypt the encrypted block sent by the client
int decrypt_msg_initializer (unsigned char * key, unsigned char * ciphertext, int ciphertext_len,
	unsigned char * iv, unsigned char * decryptedtext) {
	// Initialise the library
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	// Decrypt the ciphertext
	int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
	
	// Clean up
	EVP_cleanup();
	ERR_free_strings();

	return decryptedtext_len;
}
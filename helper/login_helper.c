#include "../header/common_header.h"
#include "../header/login_header.h"
#include "../header/kdc_crypto_header.h"

// check if username and hash of password is legit or not
int check_username_and_password_hash(char * username, unsigned char * digest) {
	FILE * fp = fopen("database/registration_database.txt", "r");

	// if the file doesn't exist, implies, user doesn't exist
	if(fp == NULL) {
		return -1;
	}

	// check for username and password in the database
	while(!feof(fp)) {
		char uname[41];
		char upass[41];

		fscanf(fp, "%s %s", uname, upass);

		// check if the username already exists
		if(strcmp(username, uname) == 0) {
			// generate SHA256 hash of the password
			unsigned char * gen_digest;
			unsigned int digest_len;
			generate_SHA256_digest((const unsigned char*)upass, strlen(upass), &gen_digest, &digest_len);

			// check if both the hash (one sent by client and one computed by KDC) matches
			if(memcmp(digest, gen_digest, 32) != 0) {
				fclose(fp);
				return -1;
			}

			fclose(fp); 
			return 1;
		}
	}

	fclose(fp);
	// login credentials are invalid or user is not registered
	return -1;
}

// function to get password from username
void get_user_password(char * username, char * password) {
	FILE * fp = fopen("database/registration_database.txt", "r");

	// get the password for the username
	while(!feof(fp)) {
		char uname[41];
		char upass[41];

		fscanf(fp, "%s %s", uname, upass);

		// check if the username already exists
		if(strcmp(username, uname) == 0) {
			strcpy(password, upass);
			fclose(fp); 
			return;
		}
	}

	fclose(fp);
	// login credentials are invalid or user is not registered
}
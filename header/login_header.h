/*
	For handling of client login
*/

// check if username and hash of password is legit or not
int check_username_and_password_hash(char *, unsigned char *);
// function to get password of a user with specified username
void get_user_password(char *, char *);
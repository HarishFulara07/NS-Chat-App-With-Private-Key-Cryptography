/*
	Header file for client
*/

// socket descriptors returned by the socket function
int chat_cli_sockfd, login_cli_sockfd;
// structure to hold the client's socket information for chat service
struct sockaddr_in chat_cli_sock;
// structure to hold the client's socket information for login service
struct sockaddr_in login_cli_sock;
// buffer for reading message sent from server
char read_buffer[1025];
// buffer for sending message sent to the server
char write_buffer[1025];
// to hold the value returned by read() function
int read_msg;
// to hold the value returned by write() function
int write_msg;
// to logout client from chat portal
int logout;
// to check if there is a message to be read before entering a command
fd_set readfd;
// max value of socket descriptor in fd_set. It is used in select function.
int max_sd;
// TGT sent by the server to the client if client's logs in successfully
struct TGT * tgt;
// The key of the communication between this client and another client on chat server
unsigned char key[20][32];
// The username of the other client to whom we are communicating with via chat
// ASSUMPTION: The user will simultaneously chat with atmost 20 other clients
// key[i] corresponds to key with user[i]
char user[20][41];
long long int key_timestamp[20];
int nonce;

// initiallizes the client to connect to server for chat
void initialize_client_for_chat();
// initiallizes the client to connect to kdc for login
void initialize_client_for_login();
// function to return max of two numbers
int MAX(int, int);
// convert int to string
char * int_to_str(int);
// function to get ciphertext and length of ciphertext from TGT
void get_ciphertext_and_len_from_tgt(char *, char *, unsigned char *);
// function to get ciphertext and length of ciphertext from login block sent by the client to the KDC
// the ciphertext contains encrypted client password and encrypted timestamp
void get_ciphertext_and_len_from_enc_block(char *, int *, unsigned char *);
void get_ciphertext_and_len_from_msg(char *, int *, unsigned char *);
void get_key_and_timestamp(unsigned char *, unsigned char *, long long int *, int);
void get_info_from_ticket(unsigned char *, unsigned char *, char *, long long int *, int);
void unsigned_to_signed_char_array(unsigned char *, char *, int);
void signed_to_unsigned_char_array(unsigned char *, char *, int);

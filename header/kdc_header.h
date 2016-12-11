/*
	header file for KDC
*/

// socket descriptors returned by the socket function
int kdc_sockfd;
/*
	* cli_sockfd is the client's socket descriptor.
	* it is returned when the server accepts a connection from the client.
	* all read-write operations will be done on this descriptor to communicate with the client
*/
int cli_sockfd;
// structure to hold the kdc's socket information
struct sockaddr_in kdc_sock;
// structure to hold the client's socket information for login service
struct sockaddr_in cli_sock;
// to get size of the structure to hold the client's socket information
int cli_sock_len;

// buffer for reading message sent from client
char read_buffer[1025];
// buffer for sending message sent to client
char write_buffer[1025];
// to hold the value returned by read() function
int read_msg;
// to hold the value returned by write() function
int write_msg;

// set of socket descriptors. It will be used to handle multiple connections at a time
fd_set fds;
// array to hold socket fd of connected sockets
int sockets[20];
// max number of connnections allowed by the kdc
int max_sockets_num;
// current number of connections
int cur_sockets_num;
// max value of socket descriptor in fd_set. It is used in select function.
int max_sd;
// socket descriptor
int sock_desc;
// logging all those users who are curently logged in
char loggedin_users[20][41];
// to avoid replay attack during login request
struct LoginRequest {
	// user who makes the request
	char username[41];
	// user can chat with max 20 other users
	long long int time;
};
struct LoginRequest login_request[20];
// to avoid replay attack while chat session key negotition
long long int chat_key_timestamp[20][20];

// server password
char KDC_PASSWORD[14];

// initiallizes the kdc
void initialize_kdc();
// convert int to string
char * int_to_str(int);
// get username and password's SHA256 digest from read buffer
void get_username_and_password_hash(char *, char *, unsigned char *);
// function to get ciphertext and length of ciphertext from login block sent by the client to the KDC
// the ciphertext contains encrypted client password and encrypted timestamp
void get_ciphertext_and_len_from_enc_block(char *, int *, unsigned char *);
// function to get ciphertext and length of ciphertext from TGT sent by the client to the KDC
// the ciphertext contains encrypted client username and encrypted timestamp
void get_ciphertext_and_len_from_tgt(char *, int *, unsigned char *);
void unsigned_to_signed_char_array(unsigned char *, char *, int);
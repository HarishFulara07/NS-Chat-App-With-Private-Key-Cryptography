/*
	header file for server
*/

// socket descriptors returned by the socket function
int ser_sockfd;
/*
	* cli_sockfd is the client's socket descriptor.
	* it is returned when the server accepts a connection from the client.
	* all read-write operations will be done on this descriptor to communicate with the client
*/
int cli_sockfd;
// structure to hold the server's socket information
struct sockaddr_in ser_sock;
// structure to hold the client's socket information
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
// sockets fd of the users who are logged in
// it will be used while processing 'msg' command
int loggedin_users_sfd[20];

// initiallizes the server
void initialize_server();
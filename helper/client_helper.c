/*
	helper client program which is used by main client program to initialize the client, i.e,
	make the client ready for connecting with the server 
*/

#include "../header/common_header.h"
#include "../header/client_header.h"

// initiallizes the client to connect to server for chat service
void initialize_client_for_chat() {
	// Intializes random number generator
	srand(time(NULL));

	// ser_port_no is the port at which server listens for chat requests
	ser_port_no = 6060;

	/*
		Create the socket
	*/
	chat_cli_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	/*
		Check whether the socket is created successfully
	*/
	if(chat_cli_sockfd < 0) {
		fprintf(stderr, "ERROR creating socket. Please try again.\n");
		exit(1);
	}

	/*
		Initialize the socket information
	*/
	bzero((char *)&chat_cli_sock, sizeof(chat_cli_sock));

	chat_cli_sock.sin_family = AF_INET;
	chat_cli_sock.sin_port = htons(ser_port_no);

	/*
		Convert the localhost address (127.0.0.2) to a network address in IPv4 family
	*/
	if(inet_pton(AF_INET, "127.0.0.2", &(chat_cli_sock.sin_addr)) <= 0) {
        fprintf(stderr,"ERROR: Invalid address.\n");
        exit(1);
    }

    /*
    	Connect to the server
    */
    if(connect(chat_cli_sockfd, (struct sockaddr *)&chat_cli_sock, sizeof(chat_cli_sock)) < 0) {
    	fprintf(stderr, "ERROR connecting. Please try again.\n");
    	exit(1);
    }
}

// initiallizes the client to connect to server for login
void initialize_client_for_login() {
	// login_port_no will be used for client login on chat portal
	kdc_port_no = 7070;

	// Initially, client is not communication with anyone
	int i;
	for (i = 0; i < 20; ++i) {
		strcpy(key[i], "\0");
		strcpy(user[i], "\0");
		key_timestamp[i] = -1;
	}

	/*
		Create the socket
	*/
	login_cli_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	/*
		Check whether the socket is created successfully
	*/
	if(login_cli_sockfd < 0) {
		fprintf(stderr, "ERROR creating socket. Please try again.\n");
		exit(1);
	}

	/*
		Initialize the socket information
	*/
	bzero((char *)&login_cli_sock, sizeof(login_cli_sock));

	login_cli_sock.sin_family = AF_INET;
	login_cli_sock.sin_port = htons(kdc_port_no);

	/*
		Convert the localhost address (127.0.0.1) to a network address in IPv4 family
	*/
	if(inet_pton(AF_INET, "127.0.0.1", &(login_cli_sock.sin_addr)) <= 0) {
        fprintf(stderr,"ERROR: Invalid address.\n");
        exit(1);
    }

    /*
    	Connect to the server
    */
    if(connect(login_cli_sockfd, (struct sockaddr *)&login_cli_sock, sizeof(login_cli_sock)) < 0) {
    	fprintf(stderr, "ERROR connecting. Please try again.\n");
    	exit(1);
    }
}

// return the max value
int MAX(int x, int y) {
	return x > y ? x : y;
}

// convert int to str
char * int_to_str(int n) {
	int len = 0;
	int tmp = n;
	int pos = 0;
	char * str;

	// handle case for 'n = 0'
	if(n == 0) {
		str = (char *)malloc((2) * sizeof(char));
		strcpy(str, "0");
		strcat(str, "\0");

		return str;
	}

	// getting the length of the int
	while(tmp > 0) {
		len++;
		tmp = tmp / 10;
	}

	tmp = n;

	int num[len];
	// creating a character array of appropriate size (size of char array = length of int + 1)
	str = (char *)malloc((len+1) * sizeof(char)); 

	// storing each digit of int 'n' to an int array
	while(tmp > 0) {
		int rem = tmp % 10;
		num[pos] = rem;
		pos++;
		tmp = tmp / 10;
	}

	// converting int to a character array (or string)
	while(pos > 0) {
		pos--;
		str[len-pos-1] = num[pos] + '0';
	}

	str[len] = '\0';

	// returning the string
	return str;
}

void unsigned_to_signed_char_array(unsigned char * unsigned_char_array, char * signed_char_array, int len) {
	int i;

	for(i = 0; i < len; ++i) {
		int tmp = (int)unsigned_char_array[i];

		if(tmp < 10) {
			strcat(signed_char_array, "00");
		}
		else if(tmp < 100) {
			strcat(signed_char_array, "0");
		}

		strcat(signed_char_array, int_to_str(tmp));
	}

	strcat(signed_char_array, "\0");
}

void signed_to_unsigned_char_array(unsigned char * unsigned_char_array, char * signed_char_array, int len) {
	int i = 0, k = 0;

	while (i < len) {
		char tmp[4];
		int j = 0;

		tmp[j] = signed_char_array[i];
		++i;
		++j;

		tmp[j] = signed_char_array[i];
		++i;
		++j;

		tmp[j] = signed_char_array[i];
		++i;
		++j;

		tmp[j] = '\0';

		int val = atoi(tmp);

		unsigned_char_array[k] = (unsigned char)val;
		++k;
	}
}

// function to get ciphertext and length of ciphertext from TGT
void get_ciphertext_and_len_from_tgt(char * read_buffer, char * ciphertext_len, unsigned char * ciphertext) {
	int i = 0, j = 0, l = strlen(read_buffer);
	char tmp[1024];

	while(read_buffer[i] != ':') {
		ciphertext_len[i] = read_buffer[i];
		++i;
	}

	ciphertext_len[i] = '\0';
	++i;

	while(j < l) {
		tmp[j] = read_buffer[i];
		++j;
		++i;
	}

	tmp[j] = '\0';

	// printf("TGT CHAR TEXT: %s\n\n", tmp);

	signed_to_unsigned_char_array(ciphertext, tmp, j);
}

// function to get ciphertext and length of ciphertext from login block sent by the client to the KDC
// the ciphertext contains encrypted client password and encrypted timestamp
void get_ciphertext_and_len_from_enc_block(char * read_buffer, int * ciphertext_len, unsigned char * ciphertext) {
	int i = 0, j = 0, l = strlen(read_buffer);
	char tmp1[5], tmp2[1024];

	while(read_buffer[i] != ':') {
		tmp1[i] = read_buffer[i];
		++i;
	}

	tmp1[i] = '\0';
	++i;

	*ciphertext_len = atoi(tmp1);

	while(i < l) {
		tmp2[j] = read_buffer[i];
		++j;
		++i;
	}

	tmp2[j] = '\0';

	signed_to_unsigned_char_array(ciphertext, tmp2, j);
}

void get_ciphertext_and_len_from_msg(char * read_buffer, int * ciphertext_len, unsigned char * ciphertext) {
	int i = 0, j = 0, l = strlen(read_buffer);
	char tmp1[5], tmp2[1024];

	while(read_buffer[i] != '-') {
		tmp1[i] = read_buffer[i];
		++i;
	}

	tmp1[i] = '\0';
	++i;

	*ciphertext_len = atoi(tmp1);

	while(i < l) {
		tmp2[j] = read_buffer[i];
		++j;
		++i;
	}

	tmp2[j] = '\0';

	signed_to_unsigned_char_array(ciphertext, tmp2, j);
}

void get_key_and_timestamp(unsigned char * decryptedtext, unsigned char * key, long long int * timestamp, int len) {
	int i = 0, j = 0;
	char tmp[20];

	while(decryptedtext[i] != ':') {
		tmp[i] = decryptedtext[i];
		++i;
	}

	tmp[i] = '\0';
	++i;
	
	while(i < len) {
		key[j] = decryptedtext[i];
		++i;
		++j;
	}

	*timestamp = atoll(tmp);
}

void get_info_from_ticket(unsigned char * decryptedtext, unsigned char * key, char * username, long long int * timestamp, int len) {
	int i = 0, j = 0;
	char tmp[20];

	while(decryptedtext[i] != ':') {
		username[i] = decryptedtext[i];
		++i;
	}

	username[i] = '\0';
	++i;

	while(decryptedtext[i] != ':') {
		tmp[j] = decryptedtext[i];
		++i;
		++j;
	}

	tmp[j] = '\0';
	++i;
	j = 0;
	
	while(i < len) {
		key[j] = decryptedtext[i];
		++i;
		++j;
	}

	*timestamp = atoll(tmp);
}
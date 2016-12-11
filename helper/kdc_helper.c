#include "../header/common_header.h"
#include "../header/kdc_header.h"

// initiallizes the kdc
void initialize_kdc() {
	int i, j;
	// kdc_port_no will be used to listen for login requests
	kdc_port_no = 7070;

	// max number of connnections allowed by the server is 20
	max_sockets_num = 20;

	cur_sockets_num = 0;
	// KDC password
	strcpy(KDC_PASSWORD, "IAMAKDCSERVER");
	
	// array to hold socket fd of connected sockets, initialized with 0
	for (i = 0; i < max_sockets_num; ++i) {
		sockets[i] = 0;
		strcpy(loggedin_users[i], "\0");
		strcpy(login_request[i].username, "\0");
		login_request[i].time = -1;

		for (j = 0; j < 20; ++j) {
			chat_key_timestamp[i][j] = -1;
		}
	}
	
	/*
		Create the sockets
	*/
	
	kdc_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	/*
		Check whether the sockets are created successfully
	*/
	if(kdc_sockfd < 0) {
		fprintf(stderr, "ERROR creating KDC socket.\n");
		exit(1);
	}

	/*
		Initialize the sockets
	*/
	bzero((char *)&kdc_sock, sizeof(kdc_sock));
	
	kdc_sock.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &(kdc_sock.sin_addr));
	kdc_sock.sin_port = htons(kdc_port_no);

	/*
		Bind the host address using bind() call
	*/
	if(bind(kdc_sockfd, (struct sockaddr *)&kdc_sock, sizeof(kdc_sock)) < 0) {
		fprintf(stderr, "ERROR on binding KDC socket.\n");
		exit(1);
	}

	/* 
		* Now start listening for the clients.
		* Here process will go in sleep mode and will wait for the incoming connection
		* The process will be able to queue upto 1024 connections at a time.
   	*/

	if(listen(kdc_sockfd, 1024) < 0) {
		fprintf(stderr, "KDC ERROR in listening to clients.\n");
		exit(1);
	}
	else {
		fprintf(stdout, "\nKDC listening to clients.\n\n");
	}
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

// get username and password's SHA256 digest from read buffer
void get_username_and_password_hash(char * read_buffer, char * username, unsigned char * digest) {
	int i = 2, j = 0, l = strlen(read_buffer);
	char tmp[1024];

	while(read_buffer[i] != ':') {
		username[j] = read_buffer[i];
		++i;
		++j;
	}

	username[j] = '\0';
	++i;
	j = 0;

	while(i < l) {
		tmp[j] = read_buffer[i];
		++i;
		++j;
	}

	tmp[j] = '\0';

	signed_to_unsigned_char_array(digest, tmp, j);
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

// function to get ciphertext and length of ciphertext from tgt sent by the client to the KDC
// the ciphertext contains encrypted client username and encrypted timestamp
void get_ciphertext_and_len_from_tgt(char * read_buffer, int * ciphertext_len, unsigned char * ciphertext) {
	int i = 2, j = 0, l = strlen(read_buffer);
	char tmp1[5], tmp2[1024];

	while(read_buffer[i] != ':') {
		tmp1[j] = read_buffer[i];
		++i;
		++j;
	}

	tmp1[j] = '\0';
	j = 0;
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
#include "../header/common_header.h"
#include "../header/server_header.h"

int main(void) {
	int i;

	// initiallizes the server, i.e, start server to listen for chat connections
	initialize_server();

	while(1) {
		// clear the socket set
		FD_ZERO(&fds);

		// add the chat socket to the set
		FD_SET(ser_sockfd, &fds);
		
		max_sd = ser_sockfd;

		// add chat sockets to fd_set
		for (i = 0 ; i < max_sockets_num ; i++) {
			sock_desc = sockets[i];

			// if valid socket descriptor then add to fd_set
			if(sock_desc > 0) {
				FD_SET(sock_desc, &fds);
			}

			// maximum value socket descriptor. It is used in select function
			if(sock_desc > max_sd) {
				max_sd = sock_desc;
			}
		}

		// wait for an activity on the chat sockets, timeout is NULL, so wait indefinitely
		// when a socket is ready to be read, select will return and fds will have those sockets
		// which are ready to be read
		select(max_sd + 1, &fds, NULL, NULL, NULL);

		// if something happened on the chat socket
		if(FD_ISSET(ser_sockfd, &fds)) {
			/*
				Accept the connection from the client.
			*/
			cli_sock_len = sizeof(cli_sock);
			cli_sockfd = accept(ser_sockfd, (struct sockaddr *)&cli_sock, &cli_sock_len);

			if(cli_sockfd < 0) {
				fprintf(stderr, "ERROR in accepting the connection.\n");
				exit(1);
			}
			// server cannot process the incoming chat request
			else if(cur_sockets_num >= max_sockets_num) {
				bzero(write_buffer, 1025);
				strcpy(write_buffer, "-1\0");
				
				write_msg = write(cli_sockfd, write_buffer, strlen(write_buffer));

				if(write_msg < 0) {
					fprintf(stderr, "ERROR in sending 'server too busy' ACK to the client.\n");
					exit(1);
				}
				else {
					fprintf(stdout, "'server too busy' ACK sent to the client.\n\n");
				}
			}
			else {
				bzero(write_buffer, 1025);
				strcpy(write_buffer, "Connection Accepted. Client OK to chat.\0");
				fprintf(stdout, "%s\n", write_buffer);
				write_msg = write(cli_sockfd, write_buffer, strlen(write_buffer));

				if(write_msg < 0) {
					fprintf(stderr, "ERROR in sending chat ACK to the client.\n");
					exit(1);
				}
				else {
					fprintf(stdout, "Chat ACK sent to the client.\n\n");
				}

				// add new socket to array of sockets
				for (i = 0; i < max_sockets_num; i++) {
					// if position is empty
					if(sockets[i] == 0) {
						sockets[i] = cli_sockfd;
						cur_sockets_num++;
						break;
					}
				}
			}
		}

		// else its some IO operation on some other socket
		for (i = 0; i < max_sockets_num; i++) {
			sock_desc = sockets[i];

			if(FD_ISSET(sock_desc, &fds)) {
				bzero(read_buffer, 1025);
				read_msg = read(sock_desc, read_buffer, 1024);
				
				// check if it was for closing, if user presses ctrl+c or closes the terminal
				if(read_msg == 0) {
					close(sock_desc);
					sockets[i] = 0;
				}
				else if(read_msg > 0) {
					// read_buffer[0] = 1 means user has sent hello message
					if(read_buffer[0] == '1') {
						char username[41];
						
						// get username from read buffer
						int i, j = 0;

						for (i = 2; i < strlen(read_buffer); ++i) {
							username[j] = read_buffer[i];
							++j;
						}

						username[j] = '\0';

						// log user as logged in in loggedin_users array
						for (j = 0; j < max_sockets_num; j++) {
							// if position is empty
							if(strcmp(loggedin_users[j], "\0") == 0) {
								strcpy(loggedin_users[j], username);
								strcat(loggedin_users[j], "\0");
								loggedin_users_sfd[j] = sock_desc;
								break;
							}
						}
					}
					// read_buffer[0] = 2 means user has sent the ticket
					else if(read_buffer[0] == '2') {
						fprintf(stdout, "Received ticket from client.\n");

						const char delim[2] = ":";
						strtok(read_buffer, delim);
						
						char * from = strtok(NULL, delim);
						char * to = strtok(NULL, delim);
						char * msg = strtok(NULL, delim);

						int j, sfd;

						// search for the receiver
						for (j = 0; j < max_sockets_num; j++) {
							// if receiver is found
							if(strcmp(loggedin_users[j], to) == 0) {
								sfd = loggedin_users_sfd[j];
								break;
							}
						}

						// message being forwarded from server to the receiver
						bzero(write_buffer, 1025);
						strcpy(write_buffer, "1:");
						strcat(write_buffer, msg);
						strcat(write_buffer, "\0");

						write_msg = write(sfd, write_buffer, strlen(write_buffer));

						if(write_msg < 0) {
							fprintf(stderr, "ERROR in sending ticket to the receiver %s.\n", to);
							exit(1);
						}
						else {
							fprintf(stdout, "Ticket sent to the receiver %s.\n\n", to);
						}

						// sending ACK to the sender
						bzero(write_buffer, 1025);
						strcpy(write_buffer, "Ticket sent successfully.");
						strcat(write_buffer, "\0");

						write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

						if(write_msg < 0) {
							fprintf(stderr, "ERROR in sending ticket ACK to the sender %s.\n", from);
							exit(1);
						}
						else {
							fprintf(stdout, "Ticket ACK sent to the sender %s\n\n", from);
						}
					}
					// read_buffer[0] = 3 means user has sent the message
					else if(read_buffer[0] == '3') {
						const char delim[2] = ":";
						strtok(read_buffer, delim);
						
						char * from = strtok(NULL, delim);
						char * to = strtok(NULL, delim);
						char * msg = strtok(NULL, delim);
						char * sign_len = strtok(NULL, delim);
						char * sign = strtok(NULL, delim);

						int j, sfd;

						// search for the receiver
						for (j = 0; j < max_sockets_num; j++) {
							// if receiver is found
							if(strcmp(loggedin_users[j], to) == 0) {
								sfd = loggedin_users_sfd[j];
								break;
							}
						}

						// message being forwarded from server to the receiver
						bzero(write_buffer, 1025);
						strcpy(write_buffer, "2:");
						strcat(write_buffer, from);
						strcat(write_buffer, ":");
						strcat(write_buffer, msg);
						strcat(write_buffer, ":");
						strcat(write_buffer, sign_len);
						strcat(write_buffer, ":");
						strcat(write_buffer, sign);
						strcat(write_buffer, "\0");

						write_msg = write(sfd, write_buffer, strlen(write_buffer));

						if(write_msg < 0) {
							fprintf(stderr, "ERROR in sending ticket to the receiver %s.\n", to);
							exit(1);
						}
						else {
							fprintf(stdout, "Message sent to the receiver %s.\n\n", to);
						}

						// sending ACK to the sender
						bzero(write_buffer, 1025);
						strcpy(write_buffer, "Message sent successfully.");
						strcat(write_buffer, "\0");

						write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

						if(write_msg < 0) {
							fprintf(stderr, "ERROR in sending ticket ACK to the sender %s.\n", from);
							exit(1);
						}
						else {
							fprintf(stdout, "Message ACK sent to the sender %s\n\n", from);
						}
					}
					// read_buffer[0] = 4 means user has sent the auth handshake message
					else if(read_buffer[0] == '4') {
						const char delim[2] = ":";
						strtok(read_buffer, delim);
						
						char * from = strtok(NULL, delim);
						char * to = strtok(NULL, delim);
						char * msg = strtok(NULL, delim);

						int j, sfd;

						// search for the receiver
						for (j = 0; j < max_sockets_num; j++) {
							// if receiver is found
							if(strcmp(loggedin_users[j], to) == 0) {
								sfd = loggedin_users_sfd[j];
								break;
							}
						}

						// message being forwarded from server to the receiver
						bzero(write_buffer, 1025);
						strcpy(write_buffer, "3:");
						strcat(write_buffer, from);
						strcat(write_buffer, ":");
						strcat(write_buffer, msg);
						strcat(write_buffer, "\0");

						write(sfd, write_buffer, strlen(write_buffer));
					}
					// read_buffer[0] = 5 means user has sent the auth handshake response
					else if(read_buffer[0] == '5') {
						const char delim[2] = ":";
						strtok(read_buffer, delim);
						
						char * from = strtok(NULL, delim);
						char * to = strtok(NULL, delim);
						char * msg = strtok(NULL, delim);

						int j, sfd;

						// search for the receiver
						for (j = 0; j < max_sockets_num; j++) {
							// if receiver is found
							if(strcmp(loggedin_users[j], to) == 0) {
								sfd = loggedin_users_sfd[j];
								break;
							}
						}

						// message being forwarded from server to the receiver
						bzero(write_buffer, 1025);
						strcpy(write_buffer, "4:");
						strcat(write_buffer, from);
						strcat(write_buffer, ":");
						strcat(write_buffer, msg);
						strcat(write_buffer, "\0");

						write(sfd, write_buffer, strlen(write_buffer));
					}
					// read_buffer[0] = 6 means user has sent the auth handshake response
					else if(read_buffer[0] == '6') {
						const char delim[2] = ":";
						strtok(read_buffer, delim);
						
						char * from = strtok(NULL, delim);
						char * to = strtok(NULL, delim);
						char * msg = strtok(NULL, delim);

						int j, sfd;

						// search for the receiver
						for (j = 0; j < max_sockets_num; j++) {
							// if receiver is found
							if(strcmp(loggedin_users[j], to) == 0) {
								sfd = loggedin_users_sfd[j];
								break;
							}
						}

						// message being forwarded from server to the receiver
						bzero(write_buffer, 1025);
						strcpy(write_buffer, "5:");
						strcat(write_buffer, from);
						strcat(write_buffer, ":");
						strcat(write_buffer, msg);
						strcat(write_buffer, "\0");

						write(sfd, write_buffer, strlen(write_buffer));
					}
					// read_buffer[0] = 7 means user wants to logout
					else if(read_buffer[0] == '7') {
						const char delim[2] = ":";
						strtok(read_buffer, delim);
						char * username = strtok(NULL, delim);

						int j;
						// remove user from loggedin_users array
						for (j = 0; j < max_sockets_num; j++) {
							// if username is found
							if(strcmp(loggedin_users[j], username) == 0) {
								strcpy(loggedin_users[j], "\0");
								loggedin_users_sfd[j] = 0;
								break;
							}
						}

						bzero(write_buffer, 1025);
						strcpy(write_buffer, "Successfully logged out.\0");

						write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

						if(write_msg < 0) {
							fprintf(stderr, "ERROR in sending logout ACK to the client.\n");
							exit(1);
						}
						else {
							fprintf(stdout, "Logout ACK sent to the client.\n\n");
						}

						// close the socket if user wants to logout
						// mark as 0 in sockets array for reuse 
						close(sock_desc);
						sockets[i] = 0;
						cur_sockets_num--;
					}
				}
			}
		}
	}
}
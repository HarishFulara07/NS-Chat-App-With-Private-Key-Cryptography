#include "../header/common_header.h"
#include "../header/kdc_header.h"
#include "../header/kdc_crypto_header.h"
#include "../header/login_header.h"

int main() {
	int i;

	// initialize the KDC, i.e, start KDC to listen for login connections
	initialize_kdc();

	while(1) {
		// clear the socket set
		FD_ZERO(&fds);

		// add the kdc socket to the set
		FD_SET(kdc_sockfd, &fds);
		
		max_sd = kdc_sockfd;

		// add sockets to fd_set
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

		// wait for an activity on the login socket, timeout is NULL, so wait indefinitely
		// when a socket is ready to be read, select will return and fds will have those sockets
		// which are ready to be read
		select(max_sd + 1, &fds, NULL, NULL, NULL);

		// if something happened on the KDC's login socket
		if(FD_ISSET(kdc_sockfd, &fds)) {
			/*
				Accept the connection from the client.
			*/
			cli_sock_len = sizeof(cli_sock);
			cli_sockfd = accept(kdc_sockfd, (struct sockaddr *)&cli_sock, &cli_sock_len);

			if(cli_sockfd < 0) {
				fprintf(stderr, "ERROR in accepting the connection.\n");
				exit(1);
			}
			// server cannot process the incoming login request
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
				strcpy(write_buffer, "Connection Accepted. Client OK to login.\0");
				write_msg = write(cli_sockfd, write_buffer, strlen(write_buffer));

				if(write_msg < 0) {
					fprintf(stderr, "ERROR in sending login ACK to the client.\n");
					exit(1);
				}
				else {
					fprintf(stdout, "Login ACK sent to the client.\n\n");
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
					// read_buffer[0] = 1 means user wants to login
					if(read_buffer[0] == '1') {
						// read1
						char username[41];
						unsigned char digest[32];
						int j, is_loggedin = 0, response_code;

						// get username and password's SHA256 digest from read buffer
						get_username_and_password_hash(read_buffer, username, digest);

						// check if username and hash of the password is legit or not
						response_code = check_username_and_password_hash(username, digest);

						// Logging client's login credentials
						printf("LOGIN CREDENTIALS\n");
						printf("Usename: %s\n", username);
						printf("Password SHA256 Hash:\n");
						BIO_dump_fp (stdout, (const char *)digest, 32);
						printf("\n");

						// if login credentials are legit
						if (response_code == 1) {
							// Before proceeding, first check whether the user is already logged in
							for(j = 0; j < max_sockets_num; ++j) {
								// user is already logged in
								if(strcmp(loggedin_users[j], username) == 0) {
									is_loggedin = 1;
									break;
								}
							}
						}

						// if user is already logged in
						if(is_loggedin) {
							response_code = 2;
						}

						bzero(write_buffer, 1025);
						
						// if response code is 1 then it means credentials sent by client are legit
						if(response_code == 1) {
							strcpy(write_buffer, "1\0");
							// write2
							write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

							if(write_msg < 0) {
								fprintf(stderr, "ERROR in sending login complete ACK to the client.\n");
								exit(1);
							}
							else {
								fprintf(stdout, "Valid login credentials ACK sent to the client.\n\n");
							}

							bzero(read_buffer, 1025);
							// getting the encrypted block (password + timestamp) from the user
							// read3
							read_msg = read(sock_desc, read_buffer, 1024);
							
							int ciphertext_len;
							unsigned char ciphertext[1024];

							get_ciphertext_and_len_from_enc_block(read_buffer, &ciphertext_len, ciphertext);

							// Logging encrypted login block
							printf("ENCRYPTED LOGIN BLOCK\n");
							printf("Ciphertext Length: %d Bytes\n", ciphertext_len);
							printf("Ciphertext:\n");
							BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
							printf("\n");

							// Buffer for the decrypted text
							unsigned char decryptedtext[100];

							int decryptedtext_len;
							
							// Decrypt the ciphertext
							decryptedtext_len = decrypt_initializer(username, ciphertext, ciphertext_len, NULL, decryptedtext);
							// add NULL terminator to decrypted text
							decryptedtext[decryptedtext_len] = '\0';

							const char delim[2] = ":";
							// get password from the decrypted ciphertext
							char decrypted_password[41];
							strcpy(decrypted_password ,strtok(decryptedtext, delim));
							strcat(decrypted_password, "\0");
							// get decrypted timestamp value from the decrypted ciphertext
							long long int decrypted_time = atoll(strtok(NULL, delim));

							// Logging decrypted login block
							printf("DECRYPTED LOGIN BLOCK\n");
							printf("Decryptedtext Length: %d Bytes\n", decryptedtext_len);
							printf("Decrypted Password: %s\n", decrypted_password);
							printf("Decrypted Timestamp: %lld\n", decrypted_time);
							printf("\n");

							// get the current server time
							// structure to hold time passed since epoch (January 1, 1970)
							struct timeval tv;
							// get current time
							gettimeofday(&tv, NULL);

							// if this block is received within 300 seconds and 
							// block timestamp is not already seen by the KDC, then it is OK
							// this measure is to prevent REPLAY attack
							if(tv.tv_sec <= decrypted_time + 300) {

								int j, flag = 0;

								// check with user's previuos login timestamp
								for(j = 0; j < max_sockets_num; ++j) {
									// if this is not the first time user is logging in
									if(strcmp(login_request[j].username, username) == 0) {
										// validate if its a replayed packet
										// it is a replay packet if decrypted time is less
										// than or equal to previously seen timestamp 
										if(login_request[j].time >= decrypted_time) {
											flag = 1;
										}
										break;
									}
								}

								// don't process the packet if it is suspicous of a replay attack
								if (flag) {
									// clean up
									// close the socket
									// mark as 0 in sockets array for reuse 
									close(sock_desc);
									sockets[i] = 0;
									cur_sockets_num--;
									continue;
								}

								fprintf(stdout, "Login block successfully decrypted & credentials verified.\n\n");

								// send TGT to the client encrypted wih server's key
								struct TGT * tgt = create_tgt(username);

								// ciphertext converted to signed char array
								char * char_ciphertext = (char *)malloc(((3 * atoi(tgt->ciphertext_len)) + 1) * sizeof(char));
								memset(char_ciphertext, '\0', (3 * atoi(tgt->ciphertext_len)) + 1);
								unsigned_to_signed_char_array(tgt->ciphertext, char_ciphertext, atoi(tgt->ciphertext_len));

								bzero(write_buffer, 1025);
								strcpy(write_buffer, tgt->ciphertext_len);
								strcat(write_buffer, ":");
								strcat(write_buffer, char_ciphertext);
								strcat(write_buffer, "\0");

								// Logging TGT
								printf("TGT\n");
								printf("Ciphertext Length: %s Bytes\n", tgt->ciphertext_len);
								printf("Ciphertext:\n");
								BIO_dump_fp (stdout, (const char *)tgt->ciphertext, atoi(tgt->ciphertext_len));
								printf("\n");

								printf("TGT CHAR CIPHERTEXT: %s\n\n", char_ciphertext);

								// write4
								write(sock_desc, write_buffer, strlen(write_buffer));

								// log user as logged-in in loggedin_users array
								for (j = 0; j < max_sockets_num; j++) {
									// if position is empty
									if(strcmp(loggedin_users[j], "\0") == 0) {
										strcpy(loggedin_users[j], username);
										strcat(loggedin_users[j], "\0");
										break;
									}
								}

								int empty_ind = -1;

								flag = 0;

								// adding username and timestamp to the LoginRequest structure
								for (j = 0; j < max_sockets_num; j++) {
									// if user is logging in for the first time on the KDC
									if(strcmp(login_request[j].username, "\0") == 0 && empty_ind == -1) {
										empty_ind = j;
									}
									// if user has already logged in previously on KDC
									if(strcmp(login_request[j].username, username) == 0) {
										login_request[j].time = decrypted_time;
										flag = 1;
										break;
									}
								}

								if(!flag) {
									strcpy(login_request[empty_ind].username, username);
									login_request[empty_ind].time = decrypted_time;
								}
							}
						}
						// if the login credentials sent by the client are not legit
						else if (response_code == -1) {
							strcpy(write_buffer, "-1\0");
							write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

							if(write_msg < 0) {
								fprintf(stderr, "ERROR in sending login fail ACK to the client.\n");
								exit(1);
							}
							else {
								fprintf(stdout, "Invalid login credentials ACK sent to the client.\n\n");
							}

							// close the socket if username is invalid
							// mark as 0 in sockets array for reuse 
							close(sock_desc);
							sockets[i] = 0;
							cur_sockets_num--;
						}
						// if the user is already logged in
						else if (response_code == 2) {
							strcpy(write_buffer, "2\0");
							write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

							if(write_msg < 0) {
								fprintf(stderr, "ERROR in sending login fail ACK to the client.\n");
								exit(1);
							}
							else {
								fprintf(stdout, "Already logged-in ACK sent to the client.\n\n");
							}

							// close the socket if user is already logged in
							// mark as 0 in sockets array for reuse 
							close(sock_desc);
							sockets[i] = 0;
							cur_sockets_num--;
						}
					}
					// read_buffer[0] = 2 means user wants a session key to chat with another user
					else if(read_buffer[0] == '2') {
						// read5
						int ciphertext_len;
						unsigned char ciphertext[1024];

						get_ciphertext_and_len_from_tgt(read_buffer, &ciphertext_len, ciphertext);

						// Logging TGT sent by client to KDC
						printf("TGT\n");
						printf("Ciphertext Length: %d Bytes\n", ciphertext_len);
						printf("Ciphertext: \n");
						BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
						printf("\n");

						// Buffer for the decrypted text
						unsigned char decryptedtext[100];

						int decryptedtext_len;

						// Decrypt the ciphertext
						decryptedtext_len = decrypt_initializer(NULL, ciphertext, ciphertext_len, NULL, decryptedtext);

						// add NULL terminator to decrypted text
						decryptedtext[decryptedtext_len] = '\0';

						const char delim[2] = ":";
						// get username from the decrypted ciphertext
						char decrypted_username[41];
						strcpy(decrypted_username ,strtok(decryptedtext, delim));
						strcat(decrypted_username, "\0");
						// get decrypted timestamp value from the decrypted ciphertext
						long long int decrypted_time = atoll(strtok(NULL, delim));

						// Logging Decrypted TGT
						printf("DECRYPTED TGT\n");
						printf("Decrypted Username: %s\n", decrypted_username);
						printf("Decrypted Time: %lld\n", decrypted_time);
						printf("\n");

						// get the current server time
						// structure to hold time passed since epoch (January 1, 1970)
						struct timeval tv;
						// get current time
						gettimeofday(&tv, NULL);

						bzero(write_buffer, 1025);

						// if TGT is received within 1 hour, then TGT is valid
						if(tv.tv_sec <= decrypted_time + 3600) {
							strcpy(write_buffer, "TGT successfully validated.\0");

							// write6
							write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

							if(write_msg < 0) {
								fprintf(stderr, "ERROR in sending TGT ACK to the client.\n");
								exit(1);
							}
							else {
								fprintf(stderr, "TGT ACK sent to the client.\n");
							}

							bzero(read_buffer, 1025);
							// getting the request asking for session key to chat with specified user
							// read7
							read_msg = read(sock_desc, read_buffer, 1024);

							int ciphertext_len;
							unsigned char ciphertext[1024];

							get_ciphertext_and_len_from_enc_block(read_buffer, &ciphertext_len, ciphertext);
							
							// Logging request for chat session key
							printf("CHAT SESSION REQUEST ENCRYPTED BLOCK\n");
							printf("Ciphertext Length: %d Bytes\n", ciphertext_len);
							printf("Ciphertext: \n");
							BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
							printf("\n");

							// Buffer for the decrypted text
							unsigned char decryptedtext[100];

							int decryptedtext_len;

							// Decrypt the ciphertext
							decryptedtext_len = decrypt_initializer(decrypted_username, ciphertext, ciphertext_len, NULL, decryptedtext);

							// add NULL terminator to decrypted text
							decryptedtext[decryptedtext_len] = '\0';

							const char delim[2] = ":";
							// get username from the decrypted ciphertext
							char to_username[41];
							strcpy(to_username, strtok(decryptedtext, delim));
							strcat(to_username, "\0");
							// get decrypted timestamp value from the decrypted ciphertext
							long long int decrypted_time = atoll(strtok(NULL, delim));

							// Logging request for chat session key
							printf("CHAT SESSION REQUEST DECRYPTED BLOCK\n");
							printf("Decrypted To Username: %s\n", to_username);
							printf("Decrypted Timestamp: %lld\n", decrypted_time);
							printf("\n");

							// get current time
							gettimeofday(&tv, NULL);

							// if it is received within 300 seconds, then it is valid
							if(tv.tv_sec <= decrypted_time + 300) {

								int j, flag = 0, k, ind;

								// check if this is a valid chat session key request packet
								for(j = 0; j < max_sockets_num; ++j) {
									// user is logged in
									if(strcmp(loggedin_users[j], decrypted_username) == 0) {
										ind = j;
										// validate if its a replayed request packet
										for(k = 0; k < 20; ++k) {
											// if we have already seen a requet wih older timestamp,
											// then the packet is suspicous of a replay attack
											if(chat_key_timestamp[j][k] >= decrypted_time) {
												flag = 1;
												break;
											}
										}
										break;
									}
								}

								// don't process the packet if it is suspicous of a replay attack
								if (flag) {
									// clean up
									// close the socket
									// mark as 0 in sockets array for reuse 
									close(sock_desc);
									sockets[i] = 0;
									cur_sockets_num--;
									continue;
								}
								else {
									// update the request_time array with the timestamp of current request
									for(k = 0; k < 20; ++k) {
										if(chat_key_timestamp[ind][k] == -1) {
											chat_key_timestamp[ind][k] = decrypted_time;
											break;
										}
									}
								}

								// create a session key for chat and encrypt it with user's password
								// along with a timestamp
								
								// A 256 bit key
								unsigned char *key = (unsigned char *)malloc((32) * sizeof(unsigned char));

								// Generate 256 bit key
								generate_key(key);

								// Logging session key				
								printf("SESSION KEY:\n");
								BIO_dump_fp (stdout, (const char *)key, 32);

								// get current time
								gettimeofday(&tv, NULL);
								long long int cur_timestamp = (long long int)tv.tv_sec;

								struct enc_block * eb = encrypt_session_key_initializer(decrypted_username, key, cur_timestamp);

								char * char_ciphertext = (char *)malloc(((3 * atoi(eb->ciphertext_len)) + 1) * sizeof(char));
								memset(char_ciphertext, '\0', (3 * atoi(eb->ciphertext_len)) + 1);
								unsigned_to_signed_char_array(eb->ciphertext, char_ciphertext, atoi(eb->ciphertext_len));

								bzero(write_buffer, 1025);
								strcpy(write_buffer, eb->ciphertext_len);
								strcat(write_buffer, ":");
								strcat(write_buffer, char_ciphertext);
								strcat(write_buffer, "\0");

								// Logging encrypted KDC response block
								printf("KDC RESPONSE BLOCK\n");
								printf("Ciphertext Length: %s Bytes\n", eb->ciphertext_len);
								printf("Ciphertext:\n");
								BIO_dump_fp (stdout, (const char *)eb->ciphertext, atoi(eb->ciphertext_len));
								printf("\n");

								// write8
								write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

								if(write_msg < 0) {
									fprintf(stderr, "ERROR in sending chat session key to the client.\n");
									exit(1);
								}
								else {
									fprintf(stderr, "Chat session key sent to the client.\n");
								}

								bzero(read_buffer, 1025);
								// getting the session key received ACK from the client
								// read9
								read(sock_desc, read_buffer, 1024);
								fprintf(stdout, "Message from client: %s\n", read_buffer);

								// Now we need to send the ticket to the client so that
								// it can give it to the client to whom it wants to chat with
								eb = encrypt_ticket_initializer(to_username, decrypted_username, key, cur_timestamp);

								free(char_ciphertext);
								char_ciphertext = (char *)malloc(((3 * atoi(eb->ciphertext_len)) + 1) * sizeof(char));
								memset(char_ciphertext, '\0', (3 * atoi(eb->ciphertext_len)) + 1);
								unsigned_to_signed_char_array(eb->ciphertext, char_ciphertext, atoi(eb->ciphertext_len));

								bzero(write_buffer, 1025);
								strcpy(write_buffer, eb->ciphertext_len);
								strcat(write_buffer, "-");
								strcat(write_buffer, char_ciphertext);
								strcat(write_buffer, "\0");

								// Logging encrypted KDC ticket block
								printf("KDC TICKET BLOCK\n");
								printf("Ciphertext Length: %s Bytes\n", eb->ciphertext_len);
								printf("Ciphertext:\n");
								BIO_dump_fp (stdout, (const char *)eb->ciphertext, atoi(eb->ciphertext_len));
								printf("\n");

								// write10
								write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

								if(write_msg < 0) {
									fprintf(stderr, "ERROR in sending ticket to the client.\n");
									exit(1);
								}
								else {
									fprintf(stderr, "Ticket sent to the client.\n");
								}
							}
						}
						else {
							strcpy(write_buffer, "TGT expired. Please login again.");

							write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

							if(write_msg < 0) {
								fprintf(stderr, "ERROR in sending TGT ACK to the client.\n");
								exit(1);
							}
							else {
								fprintf(stderr, "TGT ACK sent to the client.\n");
							}
						}
					}
					// read_buffer[0] = 3 means user wants to logout
					else if(read_buffer[0] == '3') {
						const char delim[2] = ":";
						strtok(read_buffer, delim);
						char * username = strtok(NULL, delim);

						int j, ind;

						// remove user from loggedin_users array
						for (j = 0; j < max_sockets_num; j++) {
							// if username is found
							if(strcmp(loggedin_users[j], username) == 0) {
								ind = j;
								// remove the client username
								strcpy(loggedin_users[j], "\0");
								break;
							}
						}

						for(j = 0; j < 20; ++j) {
							chat_key_timestamp[ind][j] == -1;
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

	return 0;
}
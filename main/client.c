/*
	main client program
*/
#include "../header/common_header.h"
#include "../header/client_header.h"
#include "../header/client_crypto_header.h"
#include "../header/sign_and_verify_header.h"

int main(void) {
	int choice;
	/*
		Chat Portal Home Page
	*/
	do {
		fprintf(stdout, "\n----------Welcome to the Chat Portal----------\n\n");
		fprintf(stdout, "Press 1 and hit Enter - to Login\n");
		fprintf(stdout, "Press 2 and hit Enter - to exit\n\n");
		
		fprintf(stdout, "Enter your choice: ");
		fscanf(stdin, "%d", &choice);

		if (choice == 1) {
			initialize_client_for_login();

			bzero(read_buffer, 1025);
			read_msg = read(login_cli_sockfd, read_buffer, 1024);

			if(read_msg > 0) {
				if(strcmp(read_buffer, "-1") == 0) {
					fprintf(stdout, "\nERROR: server too busy. Please try again after sometime.\n");
					continue;
				}
				else {
					fprintf(stdout, "\nMessage from server: %s\n", read_buffer);
				}
			}
			else {
				fprintf(stderr, "\nERROR in receiving login ACK from the server.\n");
				exit(1);
			}

			char username[41];
			char password[41];
			
			fprintf(stdout, "\n--------------Log into Chat Portal--------------\n\n");
			fprintf(stdout, "Enter your username: ");
			fscanf(stdin, "%s", username);
			fprintf(stdout, "Enter your password: ");
			fscanf(stdin, "%s", password);

			// generate SHA256 hash of the password
			unsigned char * digest;
			unsigned int digest_len;
			generate_SHA256_digest((const unsigned char*)password, strlen(password), &digest, &digest_len);

			/*printf("SHA256 Hash\n");
			BIO_dump_fp (stdout, (const char *)digest, digest_len);
			printf("\n");*/

			// digest converted to signed char array
			char * char_digest = (char *)malloc(((3 * digest_len) + 1) * sizeof(char));
			memset(char_digest, '\0', (3 * digest_len) + 1);
			unsigned_to_signed_char_array(digest, char_digest, (signed int)digest_len);

			// send username and SHA256 digest of the password to the server in 2:username:digest format
			bzero(write_buffer, 1025);
			strcpy(write_buffer, "1:");
			strcat(write_buffer, username);
			strcat(write_buffer, ":");
			strcat(write_buffer, char_digest);
			strcat(write_buffer, "\0");

			// write1
			write_msg = write(login_cli_sockfd, write_buffer, strlen(write_buffer));

			if(write_msg < 0) {
				fprintf(stderr, "\nERROR in sending login credentials to the server.\n");
				exit(1);
			}
			else {
				fprintf(stdout, "\nLogin credentials sent to the server.\n");
			}

			// waiting for ACK from the server for login
			bzero(read_buffer, 1025);
			// read2
			read_msg = read(login_cli_sockfd, read_buffer, 1024);

			// if ACK is received
			if(read_msg > 0) {
				// if username is valid
				if(strcmp(read_buffer, "1") == 0) {
					// encrypting client login credentials
					struct enc_block * eb = initialize_crypto(NULL, password);

					// Logging encrypted login block
					/*printf("ENCRYPTED LOGIN BLOCK\n");
					printf("Ciphertext Length: %s Bytes\n", eb->ciphertext_len);
					printf("Ciphertext:\n");
					BIO_dump_fp (stdout, (const char *)eb->ciphertext, atoi(eb->ciphertext_len));
					printf("\n");
					*/
					// ciphertext converted to signed char array
					char * char_ciphertext = (char *)malloc(((3 * atoi(eb->ciphertext_len)) + 1) * sizeof(char));
					memset(char_ciphertext, '\0', (3 * atoi(eb->ciphertext_len)) + 1);
					unsigned_to_signed_char_array(eb->ciphertext, char_ciphertext, atoi(eb->ciphertext_len));

					//printf("CHAR CIPHERTEXT: %s\n\n", char_ciphertext);

					// send encrypted block (password + timestamp) to the server
					bzero(write_buffer, 1025);
					strcpy(write_buffer, eb->ciphertext_len);
					strcat(write_buffer, ":");
					strcat(write_buffer, char_ciphertext);
					strcat(write_buffer, "\0");

					// write3
					write(login_cli_sockfd, write_buffer, strlen(write_buffer));

					// waiting to receive TGT from the server
					bzero(read_buffer, 1025);
					// read4
					read(login_cli_sockfd, read_buffer, 1024);
						
					char ciphertext_len[5];
					unsigned char ciphertext[1024];

					// retrieve ciphertext and ciphertext_len from TGT
					get_ciphertext_and_len_from_tgt(read_buffer, ciphertext_len, ciphertext);

					// Logging TGT
					/*printf("TGT\n");
					printf("Ciphertext Length: %s Bytes\n", ciphertext_len);
					printf("Ciphertext:\n");
					BIO_dump_fp (stdout, (const char *)ciphertext, atoi(ciphertext_len));
					printf("\n");*/

					// saving TGT sent by server in client's tray (memory)
					tgt = (struct TGT *)malloc(sizeof(struct TGT));
					tgt->ciphertext = (unsigned char *)malloc((1024) * sizeof(unsigned char));
					tgt->ciphertext_len = (char *)malloc(5 * sizeof(char));
					memcpy(tgt->ciphertext, ciphertext, atoi(ciphertext_len));
					strcpy(tgt->ciphertext_len, ciphertext_len);
					
					// We are okay to login now
					fprintf(stdout, "\n----------Welcome to the Chat Portal----------\n\n");
					fprintf(stdout, "Hello!!! %s\n\n", username);

					// Once we are logged in, connect to chat server
					initialize_client_for_chat();
					// Send hello message to the chat server
					bzero(write_buffer, 1025);
					strcpy(write_buffer, "1:");
					strcat(write_buffer, username);
					strcat(write_buffer, "\0");
					write(chat_cli_sockfd, write_buffer, strlen(write_buffer));

					bzero(read_buffer, 1025);
					read(chat_cli_sockfd, read_buffer, 1024);

					printf("Message from chat server: %s\n\n", read_buffer);

					logout = 0;

					while(!logout) {
						char command[21];

						fprintf(stdout, ">> ");
						fflush(stdout);

						// clear the socket set
						FD_ZERO(&readfd);
						// add the chat socket to the set
						FD_SET(chat_cli_sockfd, &readfd);
						FD_SET(STDIN_FILENO, &readfd);

						max_sd = MAX(chat_cli_sockfd, STDIN_FILENO);
						
						select(max_sd+1, &readfd, NULL, NULL, NULL);
						
						// there is a message to be read
						if(FD_ISSET(chat_cli_sockfd, &readfd)) {
							bzero(read_buffer, 1025);
							read_msg = read(chat_cli_sockfd, read_buffer, 1024);

							if(read_msg > 0) {
								char * id;
								char delim[2] = ":";

								id = strtok(read_buffer, delim);

								// id = 1 means the message is a ticket
								if(strcmp(id, "1") == 0) {
									char * msg = strtok(NULL, delim);

									// printf("RECEIVED TICKET CHAR: %s\n", msg);

									int ciphertext_len;
									unsigned char ciphertext[1024];

									get_ciphertext_and_len_from_msg(msg, &ciphertext_len, ciphertext);

									// Logging encrypted KDC response block
									/*printf("TICKET BLOCK\n");
									printf("Ciphertext Length: %d Bytes\n", ciphertext_len);
									printf("Ciphertext:\n");
									BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
									printf("\n");*/

									// Buffer for the decrypted text
									unsigned char decryptedtext[100];

									int decryptedtext_len;

									// Decrypt the ciphertext
									decryptedtext_len = decrypt_initializer(password, ciphertext, ciphertext_len, NULL, decryptedtext);

									// add NULL terminator to decrypted text
									decryptedtext[decryptedtext_len] = '\0';
									
									unsigned char decrypted_key[32];
									char from_username[41];
									long long int decrypted_time;

									get_info_from_ticket(decryptedtext, decrypted_key, from_username, &decrypted_time, decryptedtext_len);

									/*printf("TICKET BLOCK DECRYPTED BLOCK\n");
									printf("Decrypted Key\n");
									BIO_dump_fp (stdout, (const char *)decrypted_key, 32);
									printf("From: %s\n", from_username);
									printf("Expiry Timestamp: %lld\n", decrypted_time);
									printf("\n");*/

									fprintf(stdout, "\n\nReceived ticket from %s\n\n", from_username);

									// store the session key meta data before chatting 
									int i;
									for(i = 0; i < 20; ++i) {
										// empty index found to store key
										if(strcmp(key[i], "\0") == 0) {
											// store the session key for chatting
											memcpy(key[i], decrypted_key, 32);
											// store the user to whom we can chat with this key
											strcpy(user[i], from_username);
											// store the key timtamp
											// key is only valid for 60 min after the timestamp
											key_timestamp[i] = decrypted_time;
											break;
										}
									}

									// We have got the session key for chatting.
									// Before actually communicating, do a handshake
									// to authenticate each other and prevent reflection attack

									fprintf(stdout, "Initiating a two-way authentication with %s.\n\n", from_username);
									// Generate a nonce
									
									// Generated nonce value
									nonce = rand() % 100000000;

									// Encrypting the auth message
									
									char auth_msg[100];
									strcpy(auth_msg, username);
									strcat(auth_msg, "-");
									strcat(auth_msg, int_to_str(nonce));
									strcat(auth_msg, "\0");

									struct enc_block * eb = encrypt_message_initializer(decrypted_key, auth_msg);

									char * char_ciphertext = (char *)malloc(((3 * atoi(eb->ciphertext_len)) + 1) * sizeof(char));
									memset(char_ciphertext, '\0', (3 * atoi(eb->ciphertext_len)) + 1);
									unsigned_to_signed_char_array(eb->ciphertext, char_ciphertext, atoi(eb->ciphertext_len));

									// send message to chat server
									strcpy(write_buffer, "4:");
									strcat(write_buffer, username);
									strcat(write_buffer, ":");
									strcat(write_buffer, from_username);
									strcat(write_buffer, ":");
									strcat(write_buffer, eb->ciphertext_len);
									strcat(write_buffer, "-");
									strcat(write_buffer, char_ciphertext);
									strcat(write_buffer, "\0");

									write_msg = write(chat_cli_sockfd, write_buffer, strlen(write_buffer));

									if(write_msg > 0) {
										fprintf(stdout, "Sending authentication message to %s.\n\n", from_username);
									}
								}
								else if(strcmp(id, "2") == 0) {
									char * from = strtok(NULL, delim);
									char * msg = strtok(NULL, delim);
									char * sign_len = strtok(NULL, delim);
									char * sign = strtok(NULL, delim);

									//printf("SIGN TEXT: %s\n", sign);

									unsigned char sign_block[100];

									signed_to_unsigned_char_array(sign_block, sign, 3*(32+atoi(sign_len)+1)+1);

									unsigned char hkey[32];
									unsigned char signature[atoi(sign_len)];

									int i, k = 0;

									for(i = 0; i < 32; ++i) {
										hkey[i] = sign_block[i];
									}

									++i;
									
									for(k = 0; k < atoi(sign_len); ++k) {
										signature[k] = sign_block[i];
										++i; 
									}

									/*BIO_dump_fp(stdout, (const char *)sign_block, 32+atoi(sign_len)+1);
									printf("\n");
									BIO_dump_fp(stdout, (const char *)hkey, 32);
									printf("\n");
									BIO_dump_fp(stdout, (const char *)signature, atoi(sign_len));*/

									// printf("RECEIVED MSG CHAR: %s\n", msg);

									unsigned char chat_session_key[32];

									// find the chat session key to decrypt the messages
									
									for (i = 0; i < 20; ++i) {
										// Found the user who has sent us the message
										if(strcmp(from, user[i]) == 0) {
											// get the key for chat session
											memcpy(chat_session_key, key[i], 32);
											// handle session expired (if time permits)
										}
									}

									int ciphertext_len;
									unsigned char ciphertext[1024];

									get_ciphertext_and_len_from_msg(msg, &ciphertext_len, ciphertext);

									// Buffer for the decrypted text
									unsigned char decryptedtext[1024];

									int decryptedtext_len;

									// Decrypt the ciphertext
									decryptedtext_len = decrypt_msg_initializer(chat_session_key, ciphertext, ciphertext_len, NULL, decryptedtext);

									// add NULL terminator to decrypted text
									decryptedtext[decryptedtext_len] = '\0';

									int rc = verify_msg_using_hmac(decryptedtext, decryptedtext_len, signature, atoi(sign_len), hkey);

									if(rc >= 0) {
										fprintf(stdout, "\n\nReceived a message from: %s.\n", from);
										fprintf(stdout, "Message: %s\n\n", decryptedtext);
									}
									else {
										fprintf(stdout, "\n\nFailed to verify message signature.\n\n");
									}
								}
								else if(strcmp(id, "3") == 0) {
									char * from = strtok(NULL, delim);
									char * msg = strtok(NULL, delim);

									fprintf(stdout, "\n\nReceived authentication message from %s.\n\n", from);

									unsigned char chat_session_key[32];

									// find the chat session key to decrypt the messages
									int i;
									for (i = 0; i < 20; ++i) {
										// Found the user who has sent us the message
										if(strcmp(from, user[i]) == 0) {
											// get the key for chat session
											memcpy(chat_session_key, key[i], 32);
											// handle session expired (if time permits)
										}
									}

									int ciphertext_len;
									unsigned char ciphertext[1024];

									get_ciphertext_and_len_from_msg(msg, &ciphertext_len, ciphertext);

									// Buffer for the decrypted text
									unsigned char decryptedtext[1024];

									int decryptedtext_len;

									// Decrypt the ciphertext
									decryptedtext_len = decrypt_msg_initializer(chat_session_key, ciphertext, ciphertext_len, NULL, decryptedtext);

									// add NULL terminator to decrypted text
									decryptedtext[decryptedtext_len] = '\0';

									// printf("%s\n", decryptedtext);
									const char msg_delim[2] = "-";
									char * auth_from = strtok(decryptedtext, msg_delim);
									char * auth_nonce = strtok(NULL, msg_delim);

									// printf("%s %s\n", from, auth_from);

									// validate auth message
									if(strcmp(from, auth_from) == 0) {
										fprintf(stdout, "Sending authentication response to %s.\n\n", from);

										fprintf(stdout, "Sending authentication message to %s.\n\n", from);

										// Generated nonce value
										nonce = rand() % 100000000;

										// send the response to auth message
					
										// Encrypting the auth handshake response
										
										/*printf("%d\n", nonce);
										printf("%s\n", auth_nonce);*/

										char auth_msg[100];
										strcpy(auth_msg, username);
										strcat(auth_msg, "-");
										strcat(auth_msg, auth_nonce);
										strcat(auth_msg, "-");
										strcat(auth_msg, int_to_str(nonce));
										strcat(auth_msg, "\0");

										struct enc_block * eb = encrypt_message_initializer(chat_session_key, auth_msg);

										char * char_ciphertext = (char *)malloc(((3 * atoi(eb->ciphertext_len)) + 1) * sizeof(char));
										memset(char_ciphertext, '\0', (3 * atoi(eb->ciphertext_len)) + 1);
										unsigned_to_signed_char_array(eb->ciphertext, char_ciphertext, atoi(eb->ciphertext_len));

										// send message to chat server
										strcpy(write_buffer, "5:");
										strcat(write_buffer, username);
										strcat(write_buffer, ":");
										strcat(write_buffer, auth_from);
										strcat(write_buffer, ":");
										strcat(write_buffer, eb->ciphertext_len);
										strcat(write_buffer, "-");
										strcat(write_buffer, char_ciphertext);
										strcat(write_buffer, "\0");

										write(chat_cli_sockfd, write_buffer, strlen(write_buffer));
									}
								}
								else if(strcmp(id, "4") == 0) {
									char * from = strtok(NULL, delim);
									char * msg = strtok(NULL, delim);

									fprintf(stdout, "\n\nReceived authentication response from %s.\n\n", from);

									unsigned char chat_session_key[32];

									// find the chat session key to decrypt the messages
									int i;
									for (i = 0; i < 20; ++i) {
										// Found the user who has sent us the message
										if(strcmp(from, user[i]) == 0) {
											// get the key for chat session
											memcpy(chat_session_key, key[i], 32);
											// handle session expired (if time permits)
										}
									}

									int ciphertext_len;
									unsigned char ciphertext[1024];

									get_ciphertext_and_len_from_msg(msg, &ciphertext_len, ciphertext);

									// Buffer for the decrypted text
									unsigned char decryptedtext[1024];

									int decryptedtext_len;

									// Decrypt the ciphertext
									decryptedtext_len = decrypt_msg_initializer(chat_session_key, ciphertext, ciphertext_len, NULL, decryptedtext);

									// add NULL terminator to decrypted text
									decryptedtext[decryptedtext_len] = '\0';

									const char msg_delim[2] = "-";
									char * auth_from = strtok(decryptedtext, msg_delim);
									char * auth_nonce = strtok(NULL, msg_delim);
									char * resp_nonce = strtok(NULL, msg_delim);

									/*printf("%s\n", resp_nonce);
									printf("%s\n", auth_nonce);*/

									// validate auth message
									if(strcmp(from, auth_from) == 0) {
										if(strcmp(int_to_str(nonce), auth_nonce) == 0) {
											fprintf(stdout, "Two-way authentication complete with %s.\n\n", auth_from);
											fprintf(stdout, "Sending authentication response to %s.\n\n", auth_from);

											char auth_msg[100];
											strcpy(auth_msg, username);
											strcat(auth_msg, "-");
											strcat(auth_msg, resp_nonce);
											strcat(auth_msg, "\0");

											struct enc_block * eb = encrypt_message_initializer(chat_session_key, auth_msg);

											char * char_ciphertext = (char *)malloc(((3 * atoi(eb->ciphertext_len)) + 1) * sizeof(char));
											memset(char_ciphertext, '\0', (3 * atoi(eb->ciphertext_len)) + 1);
											unsigned_to_signed_char_array(eb->ciphertext, char_ciphertext, atoi(eb->ciphertext_len));

											// send message to chat server
											strcpy(write_buffer, "6:");
											strcat(write_buffer, username);
											strcat(write_buffer, ":");
											strcat(write_buffer, auth_from);
											strcat(write_buffer, ":");
											strcat(write_buffer, eb->ciphertext_len);
											strcat(write_buffer, "-");
											strcat(write_buffer, char_ciphertext);
											strcat(write_buffer, "\0");

											write(chat_cli_sockfd, write_buffer, strlen(write_buffer));
										}
										// discard the ticket
										else {
											int i;
											for(i = 0; i < 20; ++i) {
												if(strcmp(user[i], auth_from) == 0) {
													// remove the session key for chatting
													strcpy(key[i], "\0");
													// remove the user to whom we can chat with this key
													strcpy(user[i], "\0");
													// remove the key timestamp
													key_timestamp[i] = -1;
													break;
												}
											}
										}
									}
								}
								else if(strcmp(id, "5") == 0) {
									char * from = strtok(NULL, delim);
									char * msg = strtok(NULL, delim);

									fprintf(stdout, "\n\nReceived authentication response from %s.\n\n", from);

									unsigned char chat_session_key[32];

									// find the chat session key to decrypt the messages
									int i;
									for (i = 0; i < 20; ++i) {
										// Found the user who has sent us the message
										if(strcmp(from, user[i]) == 0) {
											// get the key for chat session
											memcpy(chat_session_key, key[i], 32);
											// handle session expired (if time permits)
										}
									}

									int ciphertext_len;
									unsigned char ciphertext[1024];

									get_ciphertext_and_len_from_msg(msg, &ciphertext_len, ciphertext);

									// Buffer for the decrypted text
									unsigned char decryptedtext[1024];

									int decryptedtext_len;

									// Decrypt the ciphertext
									decryptedtext_len = decrypt_msg_initializer(chat_session_key, ciphertext, ciphertext_len, NULL, decryptedtext);

									// add NULL terminator to decrypted text
									decryptedtext[decryptedtext_len] = '\0';

									const char msg_delim[2] = "-";
									char * auth_from = strtok(decryptedtext, msg_delim);
									char * auth_nonce = strtok(NULL, msg_delim);
									
									// printf("%s\n", auth_nonce);

									// validate auth message
									if(strcmp(from, auth_from) == 0) {
										if(strcmp(int_to_str(nonce), auth_nonce) == 0) {
											fprintf(stdout, "Two-way authentication completed with %s.\n\n", auth_from);
										}
									}
								}
								continue;
							}
						}

						// there is an input command to be read
						if(FD_ISSET(STDIN_FILENO, &readfd)) {
							bzero(command, 21);
							read(STDIN_FILENO, command, 20);
							command[strlen(command)-1] = '\0';
						}
						
						bzero(write_buffer, 1025);

						// send the command to the server for processing
						// send the 'logout' command
						if(strcmp(command, "logout") == 0 || strcmp(command, "/logout") == 0) {
							logout = 1;
						}
						// send the 'msg' command
						else if(strcmp(command, "msg") == 0 || strcmp(command, "/msg") == 0) {
							char to[41], msg[921];
							int ind = 0, i, flag = 0;

							fprintf(stdout, "\nWhom do you want to message: ");
							scanf("%s", to);

							// check if user already has a key to communicate with the desired user
							for(i = 0; i < 20; ++i) {
								if(strcmp(to, user[i]) == 0) {
									flag = 1;
									break;
								}
							}

							// if flag  = 0, then we don't have a key to chat with the desired user
							// we first need to negotiate the key with the KDC
							if(flag == 0) {
								fprintf(stdout, "\nNegotiating a session key with KDC to chat with %s.\n\n", to);
								
								// Logging TGT
								/*printf("TGT\n");
								printf("Ciphertext Length: %s Bytes\n", tgt->ciphertext_len);
								printf("Ciphertext:\n");
								BIO_dump_fp (stdout, (const char *)tgt->ciphertext, atoi(tgt->ciphertext_len));
								printf("\n");*/

								char * char_ciphertext = (char *)malloc(((3 * atoi(tgt->ciphertext_len)) + 1) * sizeof(char));
								memset(char_ciphertext, '\0', (3 * atoi(tgt->ciphertext_len)) + 1);
								unsigned_to_signed_char_array(tgt->ciphertext, char_ciphertext, atoi(tgt->ciphertext_len));

								// send the tgt back to the KDC so that KDC can validate us as
								// legit logged in user
								strcpy(write_buffer, "2:");
								strcat(write_buffer, tgt->ciphertext_len);
								strcat(write_buffer, ":");
								strcat(write_buffer, char_ciphertext);
								strcat(write_buffer, "\0");

								// write5
								write_msg = write(login_cli_sockfd, write_buffer, strlen(write_buffer));

								if(write_msg < 0) {
									fprintf(stderr, "\nERROR in sending 'TGT' to the KDC.\n");
									exit(1);
								}
								else {
									fprintf(stdout, "Sending TGT to KDC.\n\n");
								}

								bzero(read_buffer, 1025);
								// read6
								read(login_cli_sockfd, read_buffer, 1024);

								fprintf(stdout, "Message from KDC: %s\n\n", read_buffer);

								// encrypting request to chat with another user
								struct enc_block * eb = initialize_crypto(to, password);

								free(char_ciphertext);
								char_ciphertext = (char *)malloc(((3 * atoi(eb->ciphertext_len)) + 1) * sizeof(char));
								memset(char_ciphertext, '\0', (3 * atoi(eb->ciphertext_len)) + 1);
								unsigned_to_signed_char_array(eb->ciphertext, char_ciphertext, atoi(eb->ciphertext_len));

								// send encrypted block (receiver's username + timestamp) to the KDC
								bzero(write_buffer, 1025);
								strcpy(write_buffer, eb->ciphertext_len);
								strcat(write_buffer, ":");
								strcat(write_buffer, char_ciphertext);
								strcat(write_buffer, "\0");

								// Logging request for chat session key
								/*printf("CHAT SESSION REQUEST ENCRYPTED BLOCK\n");
								printf("Ciphertext Length: %s Bytes\n", eb->ciphertext_len);
								printf("Ciphertext: \n");
								BIO_dump_fp (stdout, (const char *)eb->ciphertext, atoi(eb->ciphertext_len));
								printf("\n");*/
								
								// write7
								write_msg = write(login_cli_sockfd, write_buffer, strlen(write_buffer));

								if(write_msg > 0) {
									fprintf(stdout, "Sending chat session key request packet to KDC.\n\n");
								}

								// waiting to receive chat session key from the KDC
								bzero(read_buffer, 1025);
								// read8
								read_msg = read(login_cli_sockfd, read_buffer, 1024);

								if(read_msg > 0) {
									fprintf(stdout, "Received ticket and chat session key from KDC.\n\n");
								}

								int ciphertext_len;
								unsigned char ciphertext[1024];

								get_ciphertext_and_len_from_enc_block(read_buffer, &ciphertext_len, ciphertext);

								// Logging encrypted KDC response block
								/*printf("KDC RESPONSE BLOCK\n");
								printf("Ciphertext Length: %d Bytes\n", ciphertext_len);
								printf("Ciphertext:\n");
								BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
								printf("\n");*/

								// Buffer for the decrypted text
								unsigned char decryptedtext[100];

								int decryptedtext_len;

								// Decrypt the ciphertext
								decryptedtext_len = decrypt_initializer(password, ciphertext, ciphertext_len, NULL, decryptedtext);

								// add NULL terminator to decrypted text
								decryptedtext[decryptedtext_len] = '\0';
								
								unsigned char decrypted_key[32];
								long long int decrypted_time;

								get_key_and_timestamp(decryptedtext, decrypted_key, &decrypted_time, decryptedtext_len);

								/*printf("KDC RESPONSE BLOCK DECRYPTED BLOCK\n");
								printf("Decrypted Key\n");
								BIO_dump_fp (stdout, (const char *)decrypted_key, 32);
								printf("Expiry Timestamp: %lld\n", decrypted_time);
								printf("\n");*/

								// store the meta data before chatting 
								for(i = 0; i < 20; ++i) {
									// empty index found to store key
									if(strcmp(key[i], "\0") == 0) {
										// store the session key for chatting
										memcpy(key[i], decrypted_key, 32);
										// store the user to whom we can chat with this key
										strcpy(user[i], to);
										// store the key timestamp
										// key is only valid for 60 min after the timestamp
										key_timestamp[i] = decrypted_time;
										break;
									}
								}

								// Notify the server that we have got the key
								bzero(write_buffer, 1025);
								strcpy(write_buffer, "Session key received.");
								strcat(write_buffer, "\0");
								
								// write9
								write(login_cli_sockfd, write_buffer, strlen(write_buffer));

								bzero(read_buffer, 1025);
								// Get the ticket from the KDC
								// read10
								read(login_cli_sockfd, read_buffer, 1024);

								// send this ticket to the user we want to chat with via chat server
								bzero(write_buffer, 1025);
								strcpy(write_buffer, "2:");
								strcat(write_buffer, username);
								strcat(write_buffer, ":");
								strcat(write_buffer, to);
								strcat(write_buffer, ":");
								strcat(write_buffer, read_buffer);
								strcat(write_buffer, "\0");
								
								//printf("RECEIVED TICKET CHAR: %s\n\n", read_buffer);

								write_msg = write(chat_cli_sockfd, write_buffer, strlen(write_buffer));

								if(write_msg > 0) {
									fprintf(stdout, "Sending ticket to %s.\n\n", to);
								}

								// receiving ACK from chat server
								bzero(read_buffer, 1025);
								read(chat_cli_sockfd, read_buffer, 1024);

								fprintf(stdout, "Message from server: %s\n\n", read_buffer);
							}
							else {
								fprintf(stdout, "What is your message: ");
								fflush(stdout);

								flag = 0;
								
								// getting message from user (can take spaces also)
								// going via this approach because scanf doesn't take spaces
								while(1) {
									char ch;
									scanf("%c", &ch);

									if(ch == '\n' && !flag) {
										flag = 1;
									}
									else if(ch == '\n' && flag) {
										msg[ind] = '\0';
										break;
									}
									else {
										msg[ind] = ch;
										ind++;
									}
								}

								// Now encrypt the actual msg using the chat session key

								unsigned char chat_session_key[32];

								// find the chat session key to chat with the desired user
								for (i = 0; i < 20; ++i) {
									// Found the user with whom we want to chat
									if(strcmp(to, user[i]) == 0) {
										// get the key for chat session
										memcpy(chat_session_key, key[i], 32);
										// handle session expired (if time permits)
									}
								}

								// Encrypting the chat message

								struct enc_block * eb = encrypt_message_initializer(chat_session_key, msg);

								char * char_ciphertext = (char *)malloc(((3 * atoi(eb->ciphertext_len)) + 1) * sizeof(char));
								memset(char_ciphertext, '\0', (3 * atoi(eb->ciphertext_len)) + 1);
								unsigned_to_signed_char_array(eb->ciphertext, char_ciphertext, atoi(eb->ciphertext_len));

								// Signing the message
								unsigned char hkey[32];
								unsigned char signature[32];
								int signature_len;

								signature_len = sign_msg_using_hmac(msg, hkey, signature);

								/*printf("%d\n", signature_len);
								BIO_dump_fp (stdout, (const char *)hkey, 32);
								BIO_dump_fp (stdout, (const char *)signature, signature_len);*/

								unsigned char combined_sign[100];
								copy_to_unsigned_char_array(combined_sign, hkey, signature, 32, signature_len);

								char * char_signature = (char *)malloc(((3 * (32+signature_len+1)) + 1) * sizeof(char));
								memset(char_signature, '\0', (3 * (32+signature_len+1)) + 1);
								unsigned_to_signed_char_array(combined_sign, char_signature, 32+signature_len+1);

								/*BIO_dump_fp (stdout, (const char *)combined_sign, 32+signature_len+1);
								printf("CHAR SIGNATURE%s\n", char_signature);*/

								// send message to chat server
								strcpy(write_buffer, "3:");
								strcat(write_buffer, username);
								strcat(write_buffer, ":");
								strcat(write_buffer, to);
								strcat(write_buffer, ":");
								strcat(write_buffer, eb->ciphertext_len);
								strcat(write_buffer, "-");
								strcat(write_buffer, char_ciphertext);
								strcat(write_buffer, ":");
								strcat(write_buffer, int_to_str(signature_len));
								strcat(write_buffer, ":");
								strcat(write_buffer, char_signature);
								strcat(write_buffer, "\0");

								write_msg = write(chat_cli_sockfd, write_buffer, strlen(write_buffer));

								if(write_msg < 0) {
									fprintf(stderr, "\nERROR in sending 'msg' command to the chat server.\n");
									exit(1);
								}

								bzero(read_buffer, 1025);
								read_msg = read(chat_cli_sockfd, read_buffer, 1024);

								if(read_msg < 0) {
									fprintf(stderr, "\nERROR in processing the 'msg' command by the server.\n");
									exit(1);
								}
								else {
									fprintf(stdout, "\n%s\n\n", read_buffer);
								}
							}
						}
						else {
							fprintf(stderr, "\nPlease enter a valid command\n\n");
						}
					}

					// close client's connection with KDC as well as chat server
					if(logout) {
						// send message to kdc to close client's connection
						bzero(write_buffer, 1025);
						strcpy(write_buffer, "3:");
						strcat(write_buffer, username);
						strcat(write_buffer, ":");
						strcat(write_buffer, "\0");

						write_msg = write(login_cli_sockfd, write_buffer, strlen(write_buffer));

						if(write_msg < 0) {
							fprintf(stderr, "\nERROR in logging out user from KDC.\n");
							exit(1);
						}

						bzero(read_buffer, 1025);
						read_msg = read(login_cli_sockfd, read_buffer, 1024);

						if(read_msg > 0) {
							fprintf(stdout, "\nMessage from KDC: %s\n", read_buffer);
						}
						else {
							fprintf(stderr, "\nERROR in receiving logout ACK from the KDC.\n");
							exit(1);
						}

						// send message to chat server to close client's connection
						bzero(write_buffer, 1025);
						strcpy(write_buffer, "7:");
						strcat(write_buffer, username);
						strcat(write_buffer, ":");
						strcat(write_buffer, "\0");

						write_msg = write(chat_cli_sockfd, write_buffer, strlen(write_buffer));

						if(write_msg < 0) {
							fprintf(stderr, "\nERROR in logging out user from server.\n");
							exit(1);
						}

						bzero(read_buffer, 1025);
						read_msg = read(chat_cli_sockfd, read_buffer, 1024);

						if(read_msg > 0) {
							fprintf(stdout, "\nMessage from chat server: %s\n\n", read_buffer);
						}
						else {
							fprintf(stderr, "\nERROR in receiving logout ACK from the chat server.\n");
							exit(1);
						}
			
						break;
					}
				}
				// error in logging in
				else if (strcmp(read_buffer, "-1") == 0) {
					fprintf(stderr, "\nMessage from server: Invalid login credentials.\n");
				}
				// error: user already logged in
				else if (strcmp(read_buffer, "2") == 0) {
					fprintf(stderr, "\nMessage from server: User already logged in.\n");
				}
			}
			else {
				fprintf(stderr, "\nERROR in receiving login ACK from the server.\n");
				exit(1);
			}
		}
		else if (choice > 2 || choice < 1) {
			fprintf(stdout, "\nInvalid choice. Please try again.\n");
		}

	} while(choice != 2);

	return(0);
}
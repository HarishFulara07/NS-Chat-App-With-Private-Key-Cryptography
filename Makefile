all:
	gcc helper/server_helper.c main/server.c -lssl -lcrypto -o server
	gcc helper/kdc_helper.c helper/kdc_crypto_helper.c helper/login_helper.c main/kdc.c -lssl -lcrypto -o kdc	
	gcc helper/client_helper.c helper/sign_and_verify_helper.c helper/client_crypto_helper.c  main/client.c -lssl -lcrypto -o client
clean:
	rm -f ./server
	rm -f ./client
	rm -f ./kdc
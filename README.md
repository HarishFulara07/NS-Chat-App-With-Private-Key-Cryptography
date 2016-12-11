# Chat App With Private Key Cryptography

### Assignment Description

This assignment builds upon the chat server (you can find basic chat server application [here] (https://github.com/HarishFulara07/NS-Basic-Web-Chat-Application)) to add additional functionality of authentication and authorization to chat messages.

Two users – lets say **Alice** and **Bob** who are both online could chat with one another enabling confidentiality and authentication. To do so you need to implement a **KDC (Key Distribution Center)** like functionality in the chat server. Alice communicates with the KDC to negotatiate a shared secret with Bob which it uses for communicating secretly and may addtionally also sign the messages (through some form of message authentication code (MAC)) to prevent against unwanted tampering. You are free to implement your own protocol to achieve the same. It may be derived from Needham Schroeder (NS) scheme or may involve more complex schemes such as those observed in Kerberos. To encrypt messages you may use openssl **EVP functions**. The shared key for each user (Alice and Bob) may be derived from their passphrases by using openssl **PBKDF functions**, that takes as input a passphrase and outputs a pseudo-random sequence of bytes.

### Assignment Summary

Alice requests the KDC to communicate with Bob and a protocol ensues between Alice and the KDC that results in the derivation of the session key which Alice and Bob eventually use to communicate. Addtionally the messages may involve MAC to protect these messages against unwanted tampering. The scheme works to protect online chat messages between two parties ONLY.

<br>

**Note**: You can find detailed information in [Report.pdf] (https://github.com/HarishFulara07/NS-Chat-App-With-Private-Key-Cryptography/blob/master/report/Report.pdf) inside **report** directory.

<br>

## How to run the application?

<------Compile the code using the following command------>

make

<------First run the server using the following command------>

./server

<------Run the client in a new terminal window using the following command------>

./client

**NOTE**: To run multiple clients, run the above command in a new terminal window for each client

<----------------------------------------------------------->

**NOTE**: My system can handle atmost 20 login connections and 20 registration connections simultaneously at a time.

The code has 2 test cases for

- testing that atmost 20 users can simultaneously register at a time
- testing that atmost 20 users can simultaneously login at a time

You can run them via the following commands:

./reg_limit_test

./login_limit_test


<----------------------------------------------------------->

PLEASE REFER TO THE DOCUMENTATION IN "documentation" DIRECTORY TO KNOW MORE ABOUT WHAT MY SYSTEM DOES, WHAT ALL ASSUMPTIONS I MADE, WHAT ALL CORNER CASES I HANDLED AND WHAT ALL ERRORS I HANDLED.

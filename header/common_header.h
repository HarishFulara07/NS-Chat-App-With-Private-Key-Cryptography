/*
	Header file common to both client and server
*/

// standard C header files
#include <stdio.h>
#include <stdlib.h>
// header file for manipulating arrays of characters
#include <string.h>
// contains data definitions for the network library routines
#include <netdb.h>
// defines prototypes, macros, variables, and the sockaddr_in structure to use with Internet 
// domain sockets
#include <netinet/in.h>
// defines prototypes for those network library routines that convert Internet address and 
// dotted-decimal notation, for example, inet_pton()
#include <arpa/inet.h>
// standard symbolic constants and types
#include <unistd.h>
// to return information about a file, for ex: size of the file, etc.
#include <sys/types.h>
#include <sys/stat.h>
// to manipulate a file descriptor
#include <fcntl.h>
// to transfer data between file descriptors
#include <sys/sendfile.h>
// header files for threads
// threads are being used for testing the program
#include <pthread.h>
#include <assert.h>
// header file to get current time
#include <sys/time.h>

// kdc_port_no will be used to listen for login requests
int kdc_port_no;
// ser_port_no will be used to listen for chat requests
int ser_port_no;
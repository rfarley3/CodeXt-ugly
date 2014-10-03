#ifndef _msgLog_c
#define _msgLog_c
// gcc -Wall -g -m32 -o msgLog.elf -fno-stack-protector -z execstack msgLog.c


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

 // series of single byte nops {nop, push eax, pop eax, nop} to help speed experiments by skipping all the loader code
#define ELF_LOADED_SIG __asm__ __volatile__( ".byte 0x90, 0x50, 0x58, 0x90\n" );
/* Attack string format:
 * 128B: 123B buffer for executable code (nop or insns must begin at offset 0) then 4B addr of &msg and then null terminator
 */


int  doServer (int sock);
void logMsg   (char* msg);


void usage (char *self) {
	fprintf (stderr, "Usage: %s port\n", self);
	exit (1);
} // end fn usage


void errmesg (char *msg) {
	fprintf (stderr, "**** %s\n", msg);
	exit (1);
} // end fn errmesg


int
serversock(int UDPorTCP, int portN, int qlen)
{
	struct sockaddr_in svr_addr;	/* my server endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/

	if (portN<0 || portN>65535 || qlen<0)	/* sanity test of parameters */
		return -2;

	bzero((char *)&svr_addr, sizeof(svr_addr));
	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = INADDR_ANY;

    /* Set destination port number */
	svr_addr.sin_port = htons(portN);

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Bind the socket */
	if (bind(sock, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) < 0)
		return -4;

	if (UDPorTCP == SOCK_STREAM && listen(sock, qlen) < 0)
		return -5;

	return sock;
} // end fn serversock


int main (int argc, char *argv[]) {
	ELF_LOADED_SIG
	int  msock;			/* master server socket		*/
	int  ssock;			/* master server socket		*/
	int  portN;			/* port number to listen */
	/*if (argc != 2) {
		usage (argv[0]);
	}
	portN = atoi (argv[1]);*/
	portN = 10000;
	msock = serversock (SOCK_STREAM, portN, 5);

	struct sockaddr_in fromAddr;	/* the from address of a client	*/
	unsigned int  fromAddrLen;		/* from-address length          */
	fromAddrLen = sizeof (fromAddr);
	printf ("Waiting for connection\n");
	ssock = accept (msock, (struct sockaddr *) &fromAddr, &fromAddrLen);
	if (ssock < 0) {
		if (errno != EINTR) {
			errmesg ("accept error\n");
		}
	}
	printf ("Connection recv'd\n");
	while (doServer (ssock) > 0) {};

	close (ssock);
	close (msock);
	
	return 0;
} // end fn main


int doServer (int sock) {
	char msg[128]; // this is the buffer that will be executed
	int bytes_read = 0;
	memset (msg, '\0', 128);
	printf ("Waiting for msg\n");
	if ((bytes_read = read (sock, msg, sizeof (msg) ) ) <= 0) {
		return bytes_read;
	} 
	printf ("Msg recv'd\n");
	if (bytes_read == 1 && msg[0] == '\n') {
		return 0;
	}
	msg[bytes_read] = 0;
	logMsg (msg);
	memset (msg, '\0', 128);
	sprintf (msg, "Msg of %uB recv'd and logged, secret: 0x%08x\n", bytes_read, (unsigned int) msg);
	if (write (sock, msg, strlen (msg) ) < 0) {
		return -1;
	}
   return bytes_read;
} // end fn doServer


void logMsg (char* msg) {
	char log_str[119]; // this is the buffer that will be overflowed, buf[(strlen (hello) - 9)]
	sprintf (log_str, "Msg in: %s", msg);
	printf ("%s", log_str);
	//fprintf to mimic ghttpd
	return;
} // end fn logString


#endif

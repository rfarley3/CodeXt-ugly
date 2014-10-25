#ifndef _msgLog_c
#define _msgLog_c
// gcc -Wall -g -m32 -o msgLog.elf -fno-stack-protector -z execstack msgLog.c

// http://h71000.www7.hp.com/doc/83final/ba554_90007/ch05s04.html

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

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define CERT_F "my.crt"
#define  KEY_F "my.key"
// PROTOCOL_TLSv1


int  doServerSSL (SSL* ssl);
int  doServer    (int sock);
void logMsg      (char* msg);


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
	
	SSL_library_init ();
	SSL_load_error_strings ();
	SSL_METHOD *meth = TLSv1_method ();
	SSL_CTX *ctx = SSL_CTX_new (meth);
	if (!ctx) {
		ERR_print_errors_fp (stderr);
      exit (1);
	}
	
	/* Load the server certificate into the SSL_CTX structure */
    if (SSL_CTX_use_certificate_file (ctx, CERT_F, SSL_FILETYPE_PEM) <= 0) {
		 ERR_print_errors_fp (stderr);
		 exit (1);
   }

  	/* Load the private-key corresponding to the server certificate */
   if (SSL_CTX_use_PrivateKey_file (ctx, KEY_F, SSL_FILETYPE_PEM) <= 0) {
   	ERR_print_errors_fp (stderr);
		exit (1);
	}
	
	/* Check if the server certificate and private-key matches */
	if (!SSL_CTX_check_private_key (ctx) ) {
		fprintf (stderr,"Private key does not match the certificate public key\n");
		exit (1);
	}
	
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
	//printf ("Waiting for connection\n");
	putchar ('1');	putchar ('\n');
	ssock = accept (msock, (struct sockaddr *) &fromAddr, &fromAddrLen);
	if (ssock < 0) {
		if (errno != EINTR) {
			errmesg ("accept error\n");
		}
	}
	//printf ("Connection recv'd\n");
	putchar ('2');	putchar ('a');	putchar ('\n');
	SSL* ssl = SSL_new (ctx);
	SSL_set_fd (ssl, ssock);
	int err = SSL_accept (ssl);
	if (err != 1) {
		//== 0 proto error or shutdown 
		// < 0 fatal
		// SSL_get_error()
   		//printf("SSL connection using %s\n", SSL_get_cipher (ssl));
		//printf("The SSL client does not have certificate.\n");
	}
	
	putchar ('2');	putchar ('b');	putchar ('\n');
	while (doServerSSL (ssl) > 0) {};
	putchar ('8');	putchar ('\n');

	SSL_shutdown (ssl);
	close (ssock);
	SSL_free (ssl);
	SSL_CTX_free (ctx);
	close (msock);
	
	return 0;
} // end fn main




int doServerSSL (SSL* ssl) {
	char msg[128]; // this is the buffer that will be executed
	int bytes_read = 0;
	memset (msg, '\0', 128);
	//printf ("Waiting for msg\n");
	putchar ('3');	putchar ('\n');
	if ((bytes_read = SSL_read (ssl, msg, sizeof (msg) - 1) ) <= 0) {
		return bytes_read;
	} 
	//printf ("Msg recv'd\n");
	putchar ('4');	putchar ('\n');
	if (bytes_read == 0 || (bytes_read == 1 && msg[0] == '\n') ) {
		return 0;
	}
	msg[bytes_read] = 0;
	putchar ('5');	putchar ('\n');
	logMsg (msg);
	putchar ('7');	putchar ('\n');
	memset (msg, '\0', 128);
	sprintf (msg, "Msg of %uB recv'd and logged, secret: 0x%08x\n", bytes_read, (unsigned int) msg);
	if (SSL_write (ssl, msg, strlen (msg) ) < 0) {
		return -1;
	}
   return bytes_read;
} // end fn doServer




void logMsg (char* msg) {
	char log_str[119]; // this is the buffer that will be overflowed, buf[(strlen (hello) - 9)]
	strcpy (log_str, "Msg in: ");
	sprintf (log_str, "Msg in: %s", msg);
	strcpy (&(log_str[8]), msg);
	putchar ('6');	putchar ('\n');
	//printf ("%s", log_str);
	//fprintf to mimic ghttpd
	//for (unsigned int i = 0; i < (msg_len + 8); i++) { putchar (log_str[i]); }
	return;
} // end fn logString


#endif

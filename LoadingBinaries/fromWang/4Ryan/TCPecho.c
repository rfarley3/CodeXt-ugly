/***********************************************************************************
 * TCPecho.c 
 *
 * simple UDP echo client
 *
 * Version: 1.0
 * Author: Xinyuan Wang
 *
 * Created on 3/29/2014
 *
 * (C) 2014 by Xinyuan Wang
 *
 * All rights reserved  
 * Xinyuan Wang, Securocs LLC
 *
 * 
************************************************************************************/

#include "xwsocklib.h" 

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define	LINELEN		128

#define DEBUG

void usage(char *self)
{
	fprintf(stderr, "Usage: %s destination port\n", self);
	exit(1);
}

void errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------------
 * TCPrecv - read TCP socket sock w/ flag for up to buflen bytes into buf

 * return:
	>=0: number of bytes read
	<0: error
 *------------------------------------------------------------------------------
 */
int
TCPrecv(int sock, char *buf, int buflen, int flag)
{
	int inbytes, n;

	if (buflen <= 0) return 0;

  /* first recv could be blocking */
	inbytes = 0; 
	n=recv(sock, &buf[inbytes], buflen - inbytes, flag);
	if (n<=0 && n != EINTR)
		return n;

	buf[n] = 0;

#ifdef DEBUG
	printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): first read %d bytes : `%s`\n", 
			   sock, buflen, flag, n, buf);
#endif /* DEBUG */

  /* subsequent tries for for anything left available */

	for (inbytes += n; inbytes < buflen; inbytes += n)
	{ 
	 	if (recv(sock, &buf[inbytes], buflen - inbytes, MSG_PEEK|MSG_DONTWAIT)<=0) /* no more to recv */
			break;
	 	n=recv(sock, &buf[inbytes], buflen - inbytes, MSG_DONTWAIT);
		buf[n] = 0;
		
#ifdef DEBUG
		printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): subsequent read %d bytes : `%s`\n", 
			   sock, buflen, flag, n, &buf[inbytes]);
#endif /* DEBUG */

	  if (n<=0) /* no more bytes to receive */
		break;
	};

#ifdef DEBUG
		printf("\tTCPrecv(sock=%d, buflen=%d): read totally %d bytes : `%s`\n", 
			   sock, buflen, inbytes, buf);
#endif /* DEBUG */

	return inbytes;
}


/*------------------------------------------------------------------------------
 * UDPecho - send input to ECHO service on specified destination and print reply
 *------------------------------------------------------------------------------
 */

int
TCPecho(char *destination, int portN)
{
	char	buf[LINELEN+1];		/* buffer for one line of text	*/
	int	sock;				/* socket descriptor, read count*/


	int	outchars, inchars;	/* characters sent and received	*/

	if ((sock = clientTCPsock(destination, portN)) < 0)
		errmesg("fail to obtain TCP socket");

	while (fgets(buf, sizeof(buf), stdin)) 
	{
		buf[LINELEN] = '\0';	/* insure line null-terminated	*/
		outchars = strlen(buf);
		(void) write(sock, buf, outchars);

#ifdef DEBUG
		printf("\tTCPecho(%s, %d): sent %d bytes to echod: `%s`\n", 
			   destination, portN, outchars, buf);
#endif /* DEBUG */

		/* read it back */
		inchars = TCPrecv(sock, buf, LINELEN-1, 0);
		if (inchars < 0)
				errmesg("socket read failed\n");
	
		fputs(buf, stdout);
	}

	return 0;
}

/*------------------------------------------------------------------------
 * main - TCP client for ECHO service
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	char *destination;
	int  portN;

	if (argc==3)
	{ 
	  destination = argv[1];
	  portN = atoi(argv[2]);
	}
	else usage(argv[0]);
		
	TCPecho(destination, portN);

	exit(0);
}


/***********************************************************************************
 * TCPechod.c 
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
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#define	QLEN		   5	/* maximum connection queue length	*/
#define	BUFSIZE		4096

#define DEBUG

void usage(char *self)
{
	fprintf(stderr, "Usage: %s port\n", self);
	exit(1);
}

void errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------
 * reaper - clean up zombie children
 *------------------------------------------------------------------------
 */
void
reaper(int signum)
{
/*
	union wait	status;
*/

	int status;

	while (wait3(&status, WNOHANG, (struct rusage *)0) >= 0)
		/* empty */;
}

/*------------------------------------------------------------------------
 * TCPechod - echo data until end of file

   return:
	 0: normal
	-1: error
 *------------------------------------------------------------------------
 */
int
TCPechod(int sock)
{
	char	buf[BUFSIZ+1];
	int	cc;

#ifdef DEBUG
	printf("***** TCPechod(%d) called\n", sock);
#endif

	while ((cc = read(sock, buf, sizeof(buf))) > 0) 
	{	buf[cc] = 0;
#ifdef DEBUG
		printf("***** TCPechod(%d): received %d bytes: `%s`\n", sock, cc, buf);
#endif
		if (write(sock, buf, cc) < 0)
			return -1;
	}

	if (cc < 0)
		return -1;

	sleep(10);
	return 0;
}

/*------------------------------------------------------------------------
 * main - Concurrent TCP server for ECHO service
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	int	 msock;			/* master server socket		*/
	int	 ssock;			/* slave server socket		*/
	int  portN;			/* port number to listen */
	struct sockaddr_in fromAddr;	/* the from address of a client	*/
	unsigned int  fromAddrLen;		/* from-address length          */

	if (argc==2)
		portN = atoi(argv[1]);
	else usage(argv[0]);

	msock = serverTCPsock(portN, 5);


	(void) signal(SIGCHLD, reaper);

	while (1) {
		fromAddrLen = sizeof(fromAddr);
		ssock = accept(msock, (struct sockaddr *)&fromAddr, &fromAddrLen);
		if (ssock < 0) {
			if (errno == EINTR)
				continue;
			errmesg("accept error\n");
		}

		switch (fork()) 
		{
			case 0:		/* child */
				close(msock);
				exit(TCPechod(ssock));
			default:	/* parent */
				(void) close(ssock);
				break;
			case -1:
				errmesg("fork error\n");
		}
	}
}


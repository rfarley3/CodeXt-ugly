/***********************************************************************************
 * serversock.c - serversock 
 *
 * Defines the serversock() function
 *
 * Version: 1.0
 * Author: Xinyuan Wang
 *
 * Created on 3/28/2014
 *
 * (C) 2014 by Xinyuan Wang
 *
 * All rights reserved  
 * Xinyuan Wang, Securocs LLC
 *
 * 
************************************************************************************/

#include "xwsocklib.h" 

#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>


/*------------------------------------------------------------------------
 * serversock - allocate & bind a server socket using TCP or UDP

   int	UDPorTCP;	/* SOCK_DGRAM or SOCK_STREAM	
   int	portN;		/* port number to listen	
   int  qlen;		/* maximum length of the server request queue

   return:
      >0: socket allocated
      <0: error
	-2: invalid parameters passed
	-3: can't allocate socket
	-4: can't bind socket
	-5: can't listen on port

 *------------------------------------------------------------------------
 */

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
}

/*------------------------------------------------------------------------
 * serverTCPsock - allocate & bind a server socket using TCP

   int	portN;		/* port number to listen	
   int  qlen;		/* maximum length of the server request queue

   return:
      >0: socket allocated
      <0: error
	-2: invalid parameters passed
	-3: can't allocate socket
	-4: can't bind socket
	-5: can't listen on port

 *------------------------------------------------------------------------
 */

inline int serverTCPsock(int portN, int qlen) 
{
  return serversock(SOCK_STREAM, portN, qlen);
}

/*------------------------------------------------------------------------
 * serverUDPsock - allocate & bind a server socket using UDP

   int	portN;		/* port number to listen	
   int  qlen;		/* maximum length of the server request queue

   return:
      >0: socket allocated
      <0: error
	-2: invalid parameters passed
	-3: can't allocate socket
	-4: can't bind socket
	-5: can't listen on port

 *------------------------------------------------------------------------
 */
inline int serverUDPsock(int portN) 
{
  return serversock(SOCK_DGRAM, portN, 0);
}


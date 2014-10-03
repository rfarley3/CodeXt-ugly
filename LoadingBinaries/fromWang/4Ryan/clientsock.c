/***********************************************************************************
 * clientsock.c - clientsock 
 *
 * Defines the clientsock() function
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
#include <arpa/inet.h>

//#define DEBUG

int fillsockaddrStr(struct sockaddr_in *sockaddr, const char *IPAddrStr, int portN)
/* return:
	0: Ok
	else: error (invalid IPAddrStr etc.)
*/
{	struct hostent	*phe;		/* pointer to host information entry	*/

//	bzero((char *)sockaddr, sizeof(struct sockaddr_in));
	memset(sockaddr, 0, sizeof(struct sockaddr_in));
	sockaddr->sin_family = AF_INET;

    /* Set port number */
	sockaddr->sin_port = htons(portN);

    /* Map host name to IPv4 address, does not work well for IPv6 */
	if ( (phe = gethostbyname(IPAddrStr)) != 0 )
//		bcopy(phe->h_addr, (char *)&sockaddr->sin_addr, phe->h_length);
		memcpy(&sockaddr->sin_addr, phe->h_addr, phe->h_length);
	else if (inet_aton(IPAddrStr, &(sockaddr->sin_addr))==0) /* invalid IP address */
		return -1;

/* version that support IPv6 
	else if (inet_pton(AF_INET, IPAddrStr, &(sockaddr->sin_addr)) != 1) 
*/

	return 0;
}

int fillsockaddrRaw(struct sockaddr_in *sockaddr, unsigned int rawIP, int portN)
{
	struct in_addr *iap = (struct in_addr *) &rawIP;

#ifdef DEBUG
	printf("*** entering fillsockaddrRaw(rawIP=%s, portN=%d)\n", 
			inet_ntoa(*iap), portN);
#endif

	memset(sockaddr, 0, sizeof(struct sockaddr_in));
	sockaddr->sin_family = AF_INET;
    /* Set port number */
	sockaddr->sin_port = htons(portN);
	/* Set IP address */
	memcpy(&sockaddr->sin_addr, iap, sizeof(struct in_addr));

	return 0;
}

/*------------------------------------------------------------------------
 * clientsock - allocate & connect a socket using TCP or UDP

   int	UDPorTCP;	/* SOCK_DGRAM or SOCK_STREAM	
   const char	*destination;	/* Domain name or IP of the destination to connect to	
   int	portN;		/* destination port number	

   return:
      >0: socket allocated
      <0: error
	-2: invalid destination address
	-3: can't allocate socket
	-4: can't connect to destination

 *------------------------------------------------------------------------
**/

int
clientsock(int UDPorTCP, const char *destination, int portN)
{
	struct hostent	*phe;		/* pointer to host information entry	*/
	struct sockaddr_in dest_addr;	/* destination endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/


	bzero((char *)&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;

    /* Set destination port number */
	dest_addr.sin_port = htons(portN);

    /* Map host name to IPv4 address, does not work well for IPv6 */
	if ( (phe = gethostbyname(destination)) != 0 )
		bcopy(phe->h_addr, (char *)&dest_addr.sin_addr, phe->h_length);
	else if (inet_aton(destination, &(dest_addr.sin_addr))==0) /* invalid destination address */
		return -2;

/* version that support IPv6 
	else if (inet_pton(AF_INET, destination, &(dest_addr.sin_addr)) != 1) 
*/

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Connect the socket */
	if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
		return -4;

	return sock;
}

/*------------------------------------------------------------------------
 * clientTCPsock - allocate & connect a socket using TCP

   char	*destination;	/* Domain name or IP of the destination to connect to	
   int	portN;		/* destination port number	

   return:
      >0: socket allocated
      <0: error
	-2: invalid destination address
	-3: can't allocate socket
	-4: can't connect to destination

 *------------------------------------------------------------------------
**/

inline int clientTCPsock(const char *destination, int portN) 
{
  return clientsock(SOCK_STREAM, destination, portN);
}

/*------------------------------------------------------------------------
 * clientUDPsock - allocate & connect a socket using UDP

   char	*destination;	/* Domain name or IP of the destination to connect to	
   int	portN;		/* destination port number	

   return:
      >0: socket allocated
      <0: error
	-2: invalid destination address
	-3: can't allocate socket
	-4: can't connect to destination

 *------------------------------------------------------------------------
**/
inline int clientUDPsock(const char *destination, int portN) 
{
  return clientsock(SOCK_DGRAM, destination, portN);
}


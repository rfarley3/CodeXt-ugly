/***********************************************************************************
 * xwsocklib.h 
 *
 * Header file for my little socket related function library
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

#ifndef _XWSOCKLIB_H
#define _XWSOCKLIB_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

int fillsockaddrStr(struct sockaddr_in *sockaddr, const char *IPAddrStr, int portN);
int fillsockaddrRaw(struct sockaddr_in *sockaddr, unsigned int rawIP, int portN);
int clientsock(int UDPorTCP, const char *destination, int portN);
int clientTCPsock(const char *destination, int portN);
int clientUDPsock(const char *destination, int portN);

int clientIPCsock(int UDPorTCP, const char *IPCSvrSockPath, const char *IPCCltSockPath);
int clientIPCTCPsock(const char *IPCSvrSockPath);
int clientIPCUDPsock(const char *IPCSvrSockPath, const char *IPCCltSockPath);


int serversock(int UDPorTCP, int portN, int qlen);
int serverTCPsock(int portN, int qlen);
int serverUDPsock(int portN);

int serverIPCsock(int UDPorTCP, const char *IPCSvrSockPath, int qlen);
int serverIPCTCPsock(const char *IPCSvrSockPath, int qlen);
int serverIPCUDPsock(const char *IPCSvrSockPath);

#endif /* _XWSOCKLIB_H */


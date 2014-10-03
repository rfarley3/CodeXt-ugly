/*
 * sfsocket.h -- shellforge socket implementation
 *               see http://www.cartel-securite.net/pbiondi/shellforge.html
 *               for more informations
 *
 * Copyright (C) 2003  Philippe Biondi <biondi@cartel-securite.fr>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifndef SFSOCKET_H
#define SFSOCKET_H


typedef unsigned int socklen_t;

/* SOCK_ constants */
enum __socket_type
{
  SOCK_STREAM = 1,              /* Sequenced, reliable, connection-based
                                   byte streams.  */
#define SOCK_STREAM SOCK_STREAM
  SOCK_DGRAM = 2,               /* Connectionless, unreliable datagrams
                                   of fixed maximum length.  */
#define SOCK_DGRAM SOCK_DGRAM
  SOCK_RAW = 3,                 /* Raw protocol interface.  */
#define SOCK_RAW SOCK_RAW
  SOCK_RDM = 4,                 /* Reliably-delivered messages.  */
#define SOCK_RDM SOCK_RDM
  SOCK_SEQPACKET = 5,           /* Sequenced, reliable, connection-based,
                                   datagrams of fixed maximum length.  */
#define SOCK_SEQPACKET SOCK_SEQPACKET
  SOCK_PACKET = 10              /* Linux specific way of getting packets
                                   at the dev level.  For writing rarp and
                                   other similar things on the user level. */
#define SOCK_PACKET SOCK_PACKET
};
	
/* Protocol families.  */
#define PF_UNSPEC       0       /* Unspecified.  */
#define PF_LOCAL        1       /* Local to host (pipes and file-domain).  */
#define PF_UNIX         PF_LOCAL /* Old BSD name for PF_LOCAL.  */
#define PF_FILE         PF_LOCAL /* Another non-standard name for PF_LOCAL.  */
#define PF_INET         2       /* IP protocol family.  */
#define PF_AX25         3       /* Amateur Radio AX.25.  */
#define PF_IPX          4       /* Novell Internet Protocol.  */
#define PF_APPLETALK    5       /* Appletalk DDP.  */
#define PF_NETROM       6       /* Amateur radio NetROM.  */
#define PF_BRIDGE       7       /* Multiprotocol bridge.  */
#define PF_ATMPVC       8       /* ATM PVCs.  */
#define PF_X25          9       /* Reserved for X.25 project.  */
#define PF_INET6        10      /* IP version 6.  */
#define PF_ROSE         11      /* Amateur Radio X.25 PLP.  */
#define PF_DECnet       12      /* Reserved for DECnet project.  */
#define PF_NETBEUI      13      /* Reserved for 802.2LLC project.  */
#define PF_SECURITY     14      /* Security callback pseudo AF.  */
#define PF_KEY          15      /* PF_KEY key management API.  */
#define PF_NETLINK      16
#define PF_ROUTE        PF_NETLINK /* Alias to emulate 4.4BSD.  */
#define PF_PACKET       17      /* Packet family.  */
#define PF_ASH          18      /* Ash.  */
#define PF_ECONET       19      /* Acorn Econet.  */
#define PF_ATMSVC       20      /* ATM SVCs.  */
#define PF_SNA          22      /* Linux SNA Project */
#define PF_IRDA         23      /* IRDA sockets.  */
#define PF_PPPOX        24      /* PPPoX sockets.  */
#define PF_WANPIPE      25      /* Wanpipe API sockets.  */
#define PF_BLUETOOTH    31      /* Bluetooth sockets.  */
#define PF_MAX          32      /* For now..  */

	/* Address families.  */
#define AF_UNSPEC       PF_UNSPEC
#define AF_LOCAL        PF_LOCAL
#define AF_UNIX         PF_UNIX
#define AF_FILE         PF_FILE
#define AF_INET         PF_INET
#define AF_AX25         PF_AX25
#define AF_IPX          PF_IPX
#define AF_APPLETALK    PF_APPLETALK
#define AF_NETROM       PF_NETROM
#define AF_BRIDGE       PF_BRIDGE
#define AF_ATMPVC       PF_ATMPVC
#define AF_X25          PF_X25
#define AF_INET6        PF_INET6
#define AF_ROSE         PF_ROSE
#define AF_DECnet       PF_DECnet
#define AF_NETBEUI      PF_NETBEUI
#define AF_SECURITY     PF_SECURITY
#define AF_KEY          PF_KEY
#define AF_NETLINK      PF_NETLINK
#define AF_ROUTE        PF_ROUTE
#define AF_PACKET       PF_PACKET
#define AF_ASH          PF_ASH
#define AF_ECONET       PF_ECONET
#define AF_ATMSVC       PF_ATMSVC
#define AF_SNA          PF_SNA
#define AF_IRDA         PF_IRDA
#define AF_PPPOX        PF_PPPOX
#define AF_WANPIPE      PF_WANPIPE
#define AF_BLUETOOTH    PF_BLUETOOTH
#define AF_MAX          PF_MAX

#define SOL_RAW         255
#define SOL_DECNET      261
#define SOL_X25         262
#define SOL_PACKET      263
#define SOL_ATM         264     /* ATM layer (cell level).  */
#define SOL_AAL         265     /* ATM Adaption Layer (packet level).  */
#define SOL_IRDA        266

typedef unsigned short int sa_family_t;
#define __SOCKADDR_COMMON(sa_prefix) \
  sa_family_t sa_prefix##family
#define __SOCKADDR_COMMON_SIZE  (sizeof (unsigned short int))

struct sockaddr
  {
     __SOCKADDR_COMMON (sa_);    /* Common data: address family and length.  */
     char sa_data[14];           /* Address data.  */
  };

typedef unsigned int in_addr_t;
typedef unsigned short in_port_t;
struct in_addr
  {
    in_addr_t s_addr;
  };

struct sockaddr_in
  {
    __SOCKADDR_COMMON (sin_);
    in_port_t sin_port;                 /* Port number.  */
    struct in_addr sin_addr;            /* Internet address.  */

    /* Pad to size of `struct sockaddr'.  */
    unsigned char sin_zero[sizeof (struct sockaddr) -
                           __SOCKADDR_COMMON_SIZE -
                           sizeof (in_port_t) -
                           sizeof (struct in_addr)];
  };

#define IP(x,y,z,t)  ((x)|(y)<<8|(z)<<16|(t)<<24)
#define htons(x) ((((x)&0xff)<<8)|(((x)>>8)&0xff))
#define ntohs(x) htons(x)
#define SA_IN(sa, ip, port) do{ (sa).sin_family=PF_INET; \
	                        (sa).sin_port=(htons(port)); \
				(sa).sin_addr.s_addr=(ip); \
			    }while(0)

		


#define SYS_socket      1               /* sys_socket(2)                */
#define SYS_bind        2               /* sys_bind(2)                  */
#define SYS_connect     3               /* sys_connect(2)               */
#define SYS_listen      4               /* sys_listen(2)                */
#define SYS_accept      5               /* sys_accept(2)                */
#define SYS_getsockname 6               /* sys_getsockname(2)           */
#define SYS_getpeername 7               /* sys_getpeername(2)           */
#define SYS_socketpair  8               /* sys_socketpair(2)            */
#define SYS_send        9               /* sys_send(2)                  */
#define SYS_recv        10              /* sys_recv(2)                  */
#define SYS_sendto      11              /* sys_sendto(2)                */
#define SYS_recvfrom    12              /* sys_recvfrom(2)              */
#define SYS_shutdown    13              /* sys_shutdown(2)              */
#define SYS_setsockopt  14              /* sys_setsockopt(2)            */
#define SYS_getsockopt  15              /* sys_getsockopt(2)            */
#define SYS_sendmsg     16              /* sys_sendmsg(2)               */
#define SYS_recvmsg     17              /* sys_recvmsg(2)               */

#define __sys_socketcall0(type, name) \
type name(void) \
{ \
	return socketcall(SYS_##name, 0); \
}

#define __sys_socketcall1(type, name, type0, arg0) \
type name(type0 arg0) \
{ \
	unsigned long arr[1];                \
	arr[0] = (long)arg0;                 \
	return socketcall(SYS_##name, arr);  \
}

#define __sys_socketcall2(type, name, type0,arg0, type1,arg1) \
type name(type0 arg0, type1 arg1) \
{ \
	unsigned long arr[2];                \
	arr[0] = (long)arg0;                 \
	arr[1] = (long)arg1;                 \
	return socketcall(SYS_##name, arr);  \
}

#define __sys_socketcall3(type, name, type0,arg0, type1,arg1, type2,arg2) \
type name(type0 arg0, type1 arg1, type2 arg2) \
{ \
	unsigned long arr[3];                \
	arr[0] = (long)arg0;                 \
	arr[1] = (long)arg1;                 \
	arr[2] = (long)arg2;                 \
	return socketcall(SYS_##name, arr);  \
}

#define __sys_socketcall4(type, name, type0,arg0, type1,arg1, type2,arg2, type3,arg3) \
type name(type0 arg0, type1 arg1, type2 arg2, type3 arg3) \
{ \
	unsigned long arr[4];                \
	arr[0] = (long)arg0;                 \
	arr[1] = (long)arg1;                 \
	arr[2] = (long)arg2;                 \
	arr[3] = (long)arg3;                 \
	return socketcall(SYS_##name, arr);  \
}

#define __sys_socketcall5(type, name, type0,arg0, type1,arg1, type2,arg2, type3,arg3, type4,arg4) \
type name(type0 arg0, type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
	unsigned long arr[5];                \
	arr[0] = (long)arg0;                 \
	arr[1] = (long)arg1;                 \
	arr[2] = (long)arg2;                 \
	arr[3] = (long)arg3;                 \
	arr[4] = (long)arg4;                 \
	return socketcall(SYS_##name, arr);  \
}

#define __sys_socketcall6(type, name, type0,arg0, type1,arg1, type2,arg2, type3,arg3, type4,arg4, type5,arg5) \
type name(type0 arg0, type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) \
{ \
	unsigned long arr[6];                \
	arr[0] = (long)arg0;                 \
	arr[1] = (long)arg1;                 \
	arr[2] = (long)arg2;                 \
	arr[3] = (long)arg3;                 \
	arr[4] = (long)arg4;                 \
	arr[5] = (long)arg5;                 \
	return socketcall(SYS_##name, arr);  \
}



inline static __sys_socketcall3(int, socket, int,domain, int,type, int,protocol)
inline static __sys_socketcall3(int, bind, int,sockfd, struct sockaddr *,my_addr, socklen_t,addrlen)
inline static __sys_socketcall3(int,connect, int,sockfd, const struct sockaddr *,serv_addr, socklen_t,addrlen)
inline static __sys_socketcall2(int,listen,int,s, int,backlog)
inline static __sys_socketcall3(int, accept, int,s, struct sockaddr *,addr, socklen_t,*addrlen);





#endif

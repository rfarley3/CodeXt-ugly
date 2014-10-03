#ifndef _libDasosfDump_h
#define _libDasosfDump_h
//
//  libDasosfDump.h
//  
//
//  Created by Ryan Farley on 3/13/12.
//  Copyright (c) 2012 George Mason University. All rights reserved.
//
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>		/* for strerror(int errno) */
#include <errno.h>
#include <stdint.h>


#include <udis86.h> // note that on the s2e machine that this was compiled as 32b
// using this ./configure --build=i686-pc-linux-gnu "CFLAGS=-m32" "CXXFLAGS=-m32" "LDFLAGS=-m32"

#ifdef IN_32b
typedef uint32_t maddr_h; // mem addresses in 32b hosts are 32b long
#define CUT_LAST_4b 0xfffffff0
#define GET_LAST_B 0x000000ff
#else
typedef uint64_t maddr_h; // mem addresses in 64b hosts are 64b long
#define CUT_LAST_4b 0xfffffffffffffff0
#define GET_LAST_B 0x00000000000000ff
#endif
typedef uint32_t maddr_d; // our forensics module dumps 32b addresses
#define UINT_2_CHAR & 0x000000ff


#ifndef UNKNOWNS
#define SYSC_UNKNOWN 1024
#define EIP_UNKNOWN 0
#define UNKNOWNS
#endif

#define EIP_GOAL_LOC 512

typedef uint32_t uint;
typedef uint8_t byte_t;
typedef enum {false, true} bool;
typedef enum {NONE, NULLS, RANDOM} Fill_type;

/* NOTE/TODO
 * This program reads in a file to a dump struct.
 * It assumes that the reader has the same sizes 
 * for all struct elements as the writer.
 * As of now the writer uses non-fixed with types:
 *   int: 4; char: 1; u_ints: 4; timeval: 8
 * Note that OSX timeval is 16...
 * 
 * Ideally the writer should be changed to use untyped 
 * vars with set lengths when writing, then the reader
 * can use an untyped reader which is converted into a
 * typed version to guarantee compatibility regardless 
 * of writer OS version changes.
 * 
 * The writer should be converted to dump out 64b addresses
 * so maddr_d becomes a uint64_t regardless of its host 
 * machine. The writer should also note what b-size was 
 * actually captured.
 *
 * There will need to be a converter for old to new dumps.
 * Or a different preamble for 64b dumps.
 */

// used to be called linux_timeval
struct dump_timeval {
   /*time_t      4B */ /*unsigned int*/ uint32_t tv_sec;  // seconds
   /*suseconds_t 4B */ /*unsigned int*/ uint32_t tv_usec; // microseconds
};

//TODO this will only run on 32b systems; 

// NOTE this is a 32b object
struct dasos_forens_deets {
   /*int*/          int32_t  check_no;        // dasosN;
   /*int*/          int32_t  pid;             // sys_getpid();
                    char     proc_name[256];  // current->comm; used to be dynamic //char* proc_name; // current->comm;
   /*unsigned int*/ uint32_t syscall;         // eax; the system call captured
   /*unsigned int*/ uint32_t secret;          // myNo; the secret sent with the system call
   /*unsigned int*/ uint32_t true_secret;     // mySOS; the actuall secret that the system was looking for
   /*unsigned int*/ maddr_d  eip;             // the physical addr of the EIP when system call was captured, note that EIP-2 should be cd80 or sysenter
         struct dump_timeval ktv;             // time of capture according to the system which captured system call 
};

#define DUMP_SIZE 1024
#define DASOSFDUMP_PREAMBLE "DUMP!!"
#define DASOSFDUMP_PREAMBLE_LEN 6
// NOTE this is a 32b object
struct dasos_forens_dump {
                    char     preamble[6];     // all dumps have a preamble header
   /*unsigned int*/ maddr_d  start_addr;      // this is the physical addr of the dump start from the system which dumped it
   /*unsigned int*/ uint32_t num_bytes;       // this is the number of bytes dumped (should always be 1024, aka DUMP_SIZE)
   struct dasos_forens_deets deets;           // further details are held in here
   /*char*/         byte_t  dump[DUMP_SIZE]; // the actual dump
};

// NOTE  this is a 32b object bc of maddr_d's typedef
struct shellcode {
   // address of buffer it resides within, look at binary to access name of symbol at this address
   /*unsigned int*/ maddr_d  addr;             // memory addr at which shellcode begins
   /*unsigned int*/ maddr_d  eip;              // addr at which shellcode was dumped (1st syscall)
   /*unsigned int*/ uint32_t syscall;          // eax of first syscall (its number)
   /*unsigned int*/ uint32_t len;              // length of shellcode
   /*char*/         byte_t   shell[DUMP_SIZE]; //char shell[DUMP_SIZE]; // shellcode proper
};



// 190 system calls, upto 32 chars each
char syscall_table[190*33];


unsigned int isThisADasosfDump (char* buf, uint len);
void initDasosfDump (struct dasos_forens_dump* dump, struct shellcode* shell);
void endDasosfDump ();
void makeSyscallTable ();
void dataStructCheck ();
void initDump (struct dasos_forens_dump* dump);
void initShell (struct shellcode* shell);
void storeShellcodeIntoDump (struct shellcode* s, struct dasos_forens_dump* d, Fill_type t, bool eip_known);
void storeDumpIntoShellcode (struct dasos_forens_dump* d, struct shellcode* s);
void readFileToMem (char* filename, struct dasos_forens_dump* dump);
void readFileToDump (char* filename, struct dasos_forens_dump* dump);
void readFileToShell (char* filename, struct shellcode* shell);
void writeDumpToFile (struct dasos_forens_dump* dump, char* filename);
void printDisasmSingle (byte_t* raw, unsigned int len);
void printDisasmRange (byte_t* raw, unsigned int len);
void printDump (struct dasos_forens_dump dump);
void printMemRange (byte_t* shell, unsigned int len);
void printShell (struct shellcode shell);
void printShellcode (struct dasos_forens_dump dump, struct shellcode shell);
void dumpShellcode (char* dump_filename, struct shellcode shell);
void writeShellcodeToFile (struct shellcode shell, char* dump_filename);


#endif

#ifndef _elf_wrapper_c
#define _elf_wrapper_c
// gcc -Wall -g -m32

// gcc -Wall -g -m32 -o elf-wrapper.concrete elf-wrapper.c
// gcc -Wall -g -m32 -o elf-wrapper elf-wrapper.c -DSYMB

#include <stdio.h>
#include <unistd.h>
//#include <signal.h>
//#ifndef UNKNOWNS
//#define SYSC_UNKNOWN 1024
//#define EIP_UNKNOWN 0
//#define LOC_UNKNOWN 0
//#define LEN_UNKNOWN 0
//#define UNKNOWNS
//#endif
//#include "../libDasosf/libDasosfDump.h"

#ifdef SYMB
#include "/home/s2e/s2e/dasos/s2e/s2e/guest/include/s2e.h" // modified s2e.h
#endif

int main (int argc, char* argv[]) {
   if (argc < 2) {
   	printf ("Error: invalid arguments\n");
		return 1;
   }
	char elf_bin[256];
	strncpy (elf_bin, argv[1], 256);
	
   #ifdef SYMB
		char buf[1024];
   	snprintf (buf, sizeof (buf), "<< About to call codext_init with elf: %s\n", elf_bin);
   	s2e_message (buf);
   	/*if (enable_multiple) {
   		s2e_codext_enableMultiple ();
   	}*/
   	//s2e_codext_init ((uint) shell, len, eip, syscall);
   	//s2e_codext_init (LOC_UNKNOWN, LEN_UNKNOWN, EIP_UNKNOWN, SYSC_UNKNOWN);
		// http://virus.bartolich.at/virus-writing-HOWTO/_html/i386-redhat8.0-linux/magic.of.elf.html
		// Default base address of ELF executables produced by ld(1) on i386 is 0x8048001
   	//s2e_codext_init (0x8048001, 10000, EIP_UNKNOWN, SYSC_UNKNOWN);
		if (!(argc > 2 && argv[2][0] == 'd')) {
   		s2e_codext_init_lua ();
		}
      /* s2e_codext_init_lua ();
		__asm__ __volatile__(
          ".byte 0x0f, 0x3f\n"
          ".byte 0x00, 0xFA, 0x08, 0x00\n"
          ".byte 0x00, 0x00, 0x00, 0x00\n"
      );*/
	#else
		printf ("<< About to exec elf: %s\n", elf_bin);
   #endif
	execl (elf_bin, elf_bin, (char *) 0);
	
	#ifdef SYMB
		s2e_kill_state (1, "<< Error spawning elf. Shouldn't be here. Ending state");
	#endif
	return 1;
} // end fn main


#endif
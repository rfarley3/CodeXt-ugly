/* shellcode-wrapper.c
 * given a raw shellcode, specified by filename, jump to array as if it were a fn
 * 
 * To compile:
 * gcc -fno-stack-protector -z execstack -o shellcode-wrapper shellcode-wrapper.c libDasosfDump.o
 * other possible things that might need to be disabled: -D_FORTIFY_SOURCE=0
 * in general visit this link: http://smashthestack.org/viewtopic.php?id=388
 * 
 * To run:
 * ./shellcode-wrapper [-d <dump file from our kernel extension> | -f <filename of shellcode; if no -f flag, then built-in hello world shell is used>] -o <offset within shellcode to begin execution>
 * e.g.
 * ./shellcode-wrapper -f ../../dumps/handcut.shell -o 2
 * ./shellcode-wrapper -d ../../dumps/ghttpd-4f3b24c4\:786.dump -o 1
 */

#include <stdio.h>
#include "libDasosfDump.h"
#include "/home/s2e/s2e/dasos/s2e/s2e/guest/include/s2e.h" // modified s2e.h
//#include <s2e.h>
//#include <string.h>

//char canary[] = "\x90\x1f\x1f\x90"; 
//void (*canar) ();
//unsigned int canary_len = 4;

char hello[] = "\xeb\x13\x59\x31\xc0\xb0\x04\x31\xdb\x43\x31\xd2"
               "\xb2\x0f\xcd\x80\xb0\x01\x4b\xcd\x80\xe8\xe8\xff"
               "\xff\xff\x48\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72"
               "\x6c\x64\x21\x0a\x0d";

char shellcode[1024]; //8];

struct dasos_forens_dump dump;  
// doesn't need to be global, but it's nice to have the globals' address range in order to be identifiable

void (*shell) ();


int main (int argc, char* argv[]) {
   FILE* SCODE;
   unsigned int i;
   int offset_in;
   unsigned int offset;
   unsigned int eip;
   unsigned int shell_len;

   
   // defaults
   //canar = (void *) canary;
   shell = (void *) hello;
   offset = 0;
   
#ifdef SYMB
   /* The guest can enable/disable forking as well as kill states at any point in the code. 
    * When forking is disabled, S2E follows only one branch outcome, even if both outcomes are feasible.
    * */
   //s2e_enable_forking ();
   //void s2e_make_symbolic(void* buf, int size, const char* name);
   //s2e_make_symbolic(&(offset), sizeof (unsigned int), "offset");
#endif
   eip = (unsigned int) hello + 16 * sizeof (char);
   shell_len = 41;
 
   for (i = 1; i < argc; i++) {
      if (argv[i][0] != '-' || (i + 1) == argc) {
         printf ("Invalid cmd line arg or not enough args\n");
         return 1;
      }
      switch (argv[i][1]) {
         case 'f' :
            i++;
            if ((SCODE = fopen (argv[i], "r") ) == NULL) {
               printf ("Invalid file\n");
               return 1;
            }
            //memcpy (shellcode, canary, sizeof (char) * canary_len);
            //fread (&(shellcode[canary_len]), sizeof (char), 1024, SCODE);
            unsigned int read = 0;
            read = fread (shellcode, sizeof (char), 1024, SCODE);
            read = read * sizeof (char);
            fclose (SCODE);
            shell = (void *) shellcode;
            eip = 0;
            shell_len = read;
            break;
         case 'd' :
            i++;
            // read in dump file
            readFileToMem (argv[i], &dump);
            // strip dump info, output EIP
            shell = (void *) dump.dump;
            eip = (unsigned int) (dump.dump) + (512 * sizeof (char) ); // per dump grab, the offset is always 512
            shell_len = 1024; // the length is always 1024
            break;
         case 'o' :
            i++;
#ifdef SYMB_OFFSET
            printf ("Offset is set to be symbolic, ignoring this argument\n");
#else
            offset_in = atoi (argv[i]);
            offset = (unsigned int) offset_in;
#endif
            break;
         default:
            printf ("Invalid arg\n");
            return 1;
      }
   }
   
   // double check that offset is within length
   if (offset > shell_len) {
      printf ("Invalid offset\n");
      s2e_kill_state (/*status*/ 1, "Invalid offset");
      return 1;
   }
   
   //s2e_rawmon_loadmodule ("shellcode", (unsigned int) shell, shell_len);
   
   char buf[1024];
   snprintf (buf, 1024, "About to call dasospreproc_init with shell: 0x%08x (offset of %d not yet applied), shell_len: %u, eip: 0x%08x\n", (unsigned int) shell, offset, shell_len, eip);
   s2e_message (buf);
   //snprintf (buf, 1024, "len addr 0x%08x, u: %u, umasked: %u, d: %d, dmasked: %d, hex: %08x", &shell_len, shell_len, (shell_len & 0xffffffff), shell_len, (shell_len & 0xffffffff), shell_len);
   //s2e_message (buf);
   s2e_dasospreproc_init ((unsigned int) shell, shell_len, eip);
   shell += offset;

   printf ("Calling shell: 0x%08x (adjusted by offset of %d), of len: %u with eip: 0x%08x\n", (unsigned int) shell, offset, shell_len, eip);
   shell ();

   s2e_kill_state (/*status*/ 1, "Shouldn't be here");
   return 0;
} // end fn main

// end shellcode-wrapper.c

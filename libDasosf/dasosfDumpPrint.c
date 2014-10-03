/* dasosfDumpPrint.c

  User space program to print DASOSF dumps

  gcc -Wall dasosfDumpPrint.c -ldisasm -o dasosfDumpPrint

*/
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

//#include <libdis.h>

#include "libDasosfDump.h"
//#include "libDasosBastard.h"


// Argv1 is the dump file
int main (int argc, char* argv[]){
   char filename[256];
   struct dasos_forens_dump dump;
   struct shellcode shell;
   struct tm *tmp;
   struct timeval local_ktv;
   FILE* INP;

   if (argc < 2)  {
      printf ("DASOSF: Usage: %s <file>\n", argv[0]);
      printf ("DASOSF: Input file can be raw or dump, auto detected\n");
      // consider printing out a directory listing of the dump files with human readable timestamps.
      //dataStructCheck ();
      exit (1);
   }
   else {
      strncpy (filename, argv[1], 256);
   }
   
   initDasosfDump (&dump, &shell);
   
   
   if ((INP = fopen (filename, "r") ) == NULL) {
      printf ("Invalid file %s\n", filename);
      exit (1);
   }
   char test_inp[DASOSFDUMP_PREAMBLE_LEN];
   unsigned int read = 0;
   read = fread (test_inp, sizeof (char), DASOSFDUMP_PREAMBLE_LEN, INP);
   fclose (INP);
   if (!isThisADasosfDump (test_inp, DASOSFDUMP_PREAMBLE_LEN) ) {
      printf ("Requesting print from a raw shell\n");
      readFileToShell (filename, &shell);
      printShell (shell);
   }
   else {
      printf ("Requesting print from a dump struct\n");
      // reads dump file into memory
      readFileToDump (filename, &dump);
      // this allows the linux struct to be typeset into local OS version (and allow that OS's localtime to function properly
      local_ktv.tv_sec = dump.deets.ktv.tv_sec;
      tmp = localtime ( &(local_ktv.tv_sec) ); //dump.deets.ktv.tv_sec) );
      printf ("Dump of %s (%d), check_no %d captured at %4d/%02d/%02d %02d:%02d:%02d.%03d, issued sycall %u from eip 0x%08x, secret: %u true_secret: %u\n", dump.deets.proc_name, dump.deets.pid, dump.deets.check_no, tmp->tm_year+1900, tmp->tm_mon, tmp->tm_mday, tmp->tm_hour, tmp->tm_min, tmp->tm_sec, dump.deets.ktv.tv_usec/1000, dump.deets.syscall, dump.deets.eip, dump.deets.secret, dump.deets.true_secret);
      // print the memory segment of the dump using a format similar to gdb's memory view window
      printDump (dump);
   }
   endDasosfDump ();
   return 0;
} // end fn main


// end dasosfDumpPrint.c

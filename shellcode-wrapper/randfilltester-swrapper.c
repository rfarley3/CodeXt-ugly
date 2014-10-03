#ifndef _randfill_shellcode_wrapper_c
#define _randfill_shellcode_wrapper_c
/* randfill-shellcode-wrapper.c
 * create random fill shellcodes, test for cd80s, jump to array as if it were a fn
 * 
 * To compile:
 * gcc -fno-stack-protector -z execstack -o shellcode-wrapper shellcode-wrapper.c libDasosfDump.o
 * other possible things that might need to be disabled: -D_FORTIFY_SOURCE=0
 * in general visit this link: http://smashthestack.org/viewtopic.php?id=388
 * 
 */

#include <stdio.h>
#include <signal.h>
#include "../libDasosf/libDasosfDump.h"
#ifdef SYMB
#include "/home/s2e/s2e/dasos/s2e/s2e/guest/include/s2e.h" // modified s2e.h
#endif

struct Signal {
   //unsigned int value;
   //char action[16];
   char comment[256];
};

struct Signal signals[32];

void randFillTest (uint bytes_len, uint tries);
#ifdef SYMB
void setSignalHandlers ();
static void signal_handler (int sig);
#endif


unsigned time_seed () {
   time_t now = time ( 0 );
   unsigned char *p = (unsigned char *)&now;
   unsigned seed = 0;
   size_t i;
   
   for ( i = 0; i < sizeof now; i++ )
      seed = seed * ( 256 + 2U ) + p[i];
   
   return seed;
}


int main (int argc, char* argv[]) {
   #ifdef SYMB
   printf ("Running the random fill tester in symbolic mode\n");
   #else
   printf ("Running the random fill tester\n");
   #endif
   fflush (stdout);
   
   #ifdef SYMB
   setSignalHandlers ();
   #endif

   
   srand ( time_seed() );
   randFillTest (1000, 1000);
   //randFillTest (10000, 1000);
   //randFillTest (100000, 100);
   //s2e_dasospreproc_fini ();
   #ifdef SYMB
   s2e_kill_state (0, "<< Ending state 0");
   //s2e_kill_state (0, "<< Ending state");
   #endif
   return 0;
} // end fn main


void randFillTest (uint bytes_len, uint tries) {
   char buf[200001];
   maddr_h curr_offset; //NOTE that this is not maddr_d bc it needs the hosts setup, there may need to be a conversion here is the host is 64b and the dumps are not
   
   char bytes[bytes_len];
   
   unsigned int try;
   for (try = 0; try < tries; try++) {   
      snprintf (buf, sizeof (buf), "<< Within randFillTest try %u of %u, buffer len %uB\n", try, tries, bytes_len);
      #ifdef SYMB
      s2e_message (buf);
      #else
      printf ("%s\n",buf);
      #endif
      unsigned int i;
      unsigned int syscall_exists = 0;
      for (i = 0; i < bytes_len; i++) {
         // from http://eternallyconfuzzled.com/arts/jsw_art_rand.aspx
         bytes[i] = (uint8_t) ((rand () * (1.0 / (RAND_MAX + 1.0) ) ) * 256);
         if (bytes[i] == 0x80 && i > 0 && bytes[i-1] == 0xcd) {
            syscall_exists++;
         }
      }
      // be sure to save to file if need be, or just parse the output in debug.txt later
      if (syscall_exists == 0) {
         // do nothing for now, skip this case
         // there is still the chance that a random instruction will write to within itself and create a cd80
         buf[0] = '\0';
         //char buf2[3];
         //buf2[2] = '\0';
         for (i = 0; i < bytes_len; i++) {
            //snprintf (buf2, sizeof (buf2), "%02x", bytes[i]);
            snprintf (&(buf[i*2]), 3, "%02x", bytes[i]);
            //strncat (buf, buf2, 2);
         }
         //strcat (buf, "\n");
         #ifdef SYMB
         s2e_message (buf);
         #else
         printf ("%s\n", buf);
         #endif
      }
      else {
         snprintf (buf, sizeof (buf), "<< Found %u syscalls within buffer of size %uB\n", syscall_exists, bytes_len);
         printf ("%s\n",buf);
         curr_offset = 0;
         #ifdef SYMB
         s2e_message (buf);
         unsigned int i;
         for (i = 0; i < bytes_len; i++) {
            curr_offset = (maddr_h) s2e_dasospreproc_createFork (i);
            if (curr_offset != 0xffffffff) {
               // double check that offset is within length
               if (curr_offset > bytes_len) {
                  snprintf (buf, sizeof (buf), "!! Error: invalid offset %u", curr_offset);
                  s2e_kill_state (1, buf);
                  printf ("%s\n", buf);
                  exit (1);
               }
               void (*shell) () = (void *) &(bytes[0]);
               snprintf (buf, sizeof (buf), "<< About to call dasospreproc_init with shell: 0x%08x (offset of %d not yet applied), shell_len: %u\n", (uint) shell, curr_offset, bytes_len);
               s2e_message (buf);
               s2e_dasospreproc_init ((uint) shell, bytes_len, EIP_UNKNOWN, SYSC_UNKNOWN);
               shell += curr_offset; 
               printf ("<< Calling shell: 0x%08x (adjusted by offset of %u), of len: %u\n", (uint) shell, curr_offset, bytes_len);
               shell ();
               s2e_kill_state (1, "!! Error: Shouldn't be here");
               exit (1);
            } // end if not 0
            else {
               snprintf (buf, sizeof (buf), "<< Looping fork, currently at %u", i);
               s2e_warning (buf);
            } // end if 0
         } // end for each offset
         #endif
      } // end if syscall found
   } // end for each try
   return;
} // end fn randFillTest





#ifdef SYMB
void setSignalHandlers () {
   unsigned int i;
   for (i = 0; i < 32; i++) {
      //signals[i].value = i;
      signals[i].comment[0] = '\0';
   }
   
   // values are architecture dependent, these are x86
   strncpy (signals[0].comment, "Unknown signal", 256);
   strncpy (signals[1].comment, "SIGHUP Hangup detected on controlling terminal", 256);
   strncpy (signals[2].comment, "SIGINT Term Interrupt from keyboard", 256);
   strncpy (signals[3].comment, "SIGQUIT Core Quit from keyboard", 256);
   strncpy (signals[4].comment, "SIGILL Core Illegal Instruction", 256);
   strncpy (signals[5].comment, "SIGTRAP Core Trace/breakpoint trap", 256);
   strncpy (signals[6].comment, "SIGABRT Core Abort signal from abort(3)", 256);
   strncpy (signals[7].comment, "SIGBUS Core Bus error (bad memory access)", 256);
   strncpy (signals[8].comment, "SIGFPE Core Floating point exception", 256);
   strncpy (signals[9].comment, "SIGKILL Term Kill signal", 256);
   strncpy (signals[10].comment, "SIGUSR1 Term User-defined signal 1", 256);
   strncpy (signals[11].comment, "SIGSEGV Core Invalid memory reference", 256);
   strncpy (signals[12].comment, "SIGUSR2 Term User-defined signal 2", 256);
   strncpy (signals[13].comment, "SIGPIPE Term Broken pipe: write to pipe with no readers", 256);
   strncpy (signals[14].comment, "SIGALRM Term Timer signal from alarm(2)", 256);
   strncpy (signals[15].comment, "SIGTERM Term Termination signal", 256);
   strncpy (signals[16].comment, "SIGSTKFLT Term Stack fault on coprocessor (unused)", 256);
   strncpy (signals[17].comment, "SIGCHLD Ign Child stopped or terminated", 256);
   strncpy (signals[18].comment, "SIGCONT Cont Continue if stopped", 256);
   strncpy (signals[19].comment, "SIGSTOP Stop Stop process", 256);
   strncpy (signals[20].comment, "SIGTSTP Stop Stop typed at tty", 256);
   strncpy (signals[21].comment, "SIGTTIN Stop tty input for background process", 256);
   strncpy (signals[22].comment, "SIGTTOU Stop tty output for background process", 256);
   strncpy (signals[23].comment, "SIGURG Ign Urgent condition on socket (4.2BSD)", 256);
   strncpy (signals[24].comment, "SIGXCPU Core CPU time limit exceeded (4.2BSD)", 256);
   strncpy (signals[25].comment, "SIGXFSZ Core File size limit exceeded (4.2BSD)", 256);
   strncpy (signals[26].comment, "SIGVTALRM Term Virtual alarm clock (4.2BSD)", 256);
   strncpy (signals[27].comment, "SIGPROF Term Profiling timer expired", 256);
   strncpy (signals[28].comment, "SIGWINCH Ign Window resize signal (4.3BSD, Sun)", 256);
   strncpy (signals[29].comment, "SIGIO Term I/O now possible (4.2BSD) or SIGPOLL Term Pollable event (Sys V)", 256);
   strncpy (signals[30].comment, "SIGPWR Term Power failure (System V)", 256);
   strncpy (signals[31].comment, "SIGSYS Core Bad argument to routine (SVr4)", 256);

   // other arch values, (not all the above have all their options listed below)
   // see this website: http://www.kernel.org/doc/man-pages/online/pages/man7/signal.7.html
   //strncpy (signals[16].comment, "SIGUSR1 Term User-defined signal 1", 256);
   //strncpy (signals[17].comment, "SIGUSR2 Term User-defined signal 2", 256);
   //strncpy (signals[30].comment, "SIGUSR1 Term User-defined signal 1", 256);
   //strncpy (signals[31].comment, "SIGUSR2 Term User-defined signal 2", 256);
   //strncpy (signals[18].comment, "SIGCHLD Ign Child stopped or terminated", 256);
   //strncpy (signals[20].comment, "SIGCHLD Ign Child stopped or terminated", 256);
   //strncpy (signals[19].comment, "SIGCONT Cont Continue if stopped", 256);
   //strncpy (signals[25].comment, "SIGCONT Cont Continue if stopped", 256);
   //strncpy (signals[17].comment, "SIGSTOP Stop Stop process", 256);
   //strncpy (signals[23].comment, "SIGSTOP Stop Stop process", 256);
   //strncpy (signals[18].comment, "SIGTSTP Stop Stop typed at tty", 256);
   //strncpy (signals[24].comment, "SIGTSTP Stop Stop typed at tty", 256);
   //strncpy (signals[26].comment, "SIGTTIN Stop tty input for background process", 256);
   //strncpy (signals[27].comment, "SIGTTOU Stop tty output for background process", 256);
   //strncpy (signals[10].comment, "SIGBUS Core Bus error (bad memory access)", 256);
   //strncpy (signals[29].comment, "SIGPROF Term Profiling timer expired", 256);
   //strncpy (signals[12].comment, "SIGSYS Core Bad argument to routine (SVr4)", 256);
   //strncpy (signals[16].comment, "SIGURG Ign Urgent condition on socket (4.2BSD)", 256);
   //strncpy (signals[21].comment, "SIGURG Ign Urgent condition on socket (4.2BSD)", 256);
   //strncpy (signals[28].comment, "SIGVTALRM Term Virtual alarm clock (4.2BSD)", 256);
   //strncpy (signals[30].comment, "SIGXCPU Core CPU time limit exceeded (4.2BSD)", 256);
   //strncpy (signals[31].comment, "SIGXFSZ Core File size limit exceeded (4.2BSD)", 256);
   //strncpy (signals[].comment, "", 256);
   //strncpy (signals[].comment, "", 256);
   
   // The signals SIGKILL and SIGSTOP cannot be caught, blocked, or ignored.
   for (i = 1; i < 32; i++) {
      if (signals[i].comment[0] != '\0') {
         signal (i, signal_handler);
      }
   }
   
   return;
} // end fn setSignalHandlers
   
static void signal_handler (int sig) {
   /*switch (sig) {
    case SIGSEGV:
    case SIGILL:*/
   char buf[256];
   snprintf (buf, sizeof (buf), "!! Caught fatal signal: %d: %s", sig, (sig >= 32) ? signals[0].comment : signals[sig].comment);
   printf ("%s\n", buf);
   // if there is any info you want to print out, here is the place...
   //s2e_dasospreproc_fini ();
   s2e_kill_state (1, buf);
   abort ();
   /*break;
   }*/
} // end fn signal_handler
#endif


#endif
// end randfill-shellcode-wrapper.c
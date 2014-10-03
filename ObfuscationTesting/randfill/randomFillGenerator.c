#ifndef _randfill_gen_c
#define _randfill_gen_c
/* randomFillTester.c
 * Produce 10,000   1K buffers
 *          1,000  10K
 *            100 100K
 * See if have any cd80, if so output them to file and see if any have eax < 512 upon that syscall from any offset
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
#include <string.h>             /* for strerror(int errno) */
#include <errno.h>
#include <stdint.h>

//#include <signal.h>
//#include "../libDasosf/libDasosfDump.h"

#define MAX_VALUE 256
#define PERC_THRESHOLD 1.0    // maximum % from theoretical any particular value can occur and still call this uniformly random


unsigned time_seed () {
   time_t now = time ( 0 );
   unsigned char *p = (unsigned char *)&now;
   unsigned seed = 0;
   size_t i;
 
   for ( i = 0; i < sizeof now; i++ )
      seed = seed * ( MAX_VALUE + 2U ) + p[i];

   return seed;
}


int main (int argc, char* argv[]) {
   unsigned combos = 3;         // use same counter for both _sizes and _its to act as a combination
   unsigned buf_sizes[combos];  // the length of the random buffer to generate
   buf_sizes[0] = 1024;
   buf_sizes[1] = 10240;
   buf_sizes[2] = 102400;
   unsigned buf_its[combos];    // the number of buffers to generate per _size
   buf_its[0] = 1000;
   buf_its[1] = 100;
   buf_its[2] = 10;
   
   
   
   unsigned syscalls = 0;
   int distribution[MAX_VALUE];
   unsigned i;
   for (i = 0; i < MAX_VALUE; i++) {
      distribution[i] = 0;
   } //memset (distribution, '\0', 256 * sizeof (unsigned) ); 
   
   srand ( time_seed() );
   
   unsigned combo;
   for (combo = 0; combo < combos; combo++) {
      printf ("Buffer size: %u, its: %u, combo: %u\n", buf_sizes[combo], buf_its[combo], combo);
      uint8_t buf[buf_sizes[combo]];
      //buffersInvolved[it] = 0;
   
      for (i = 0; i < buf_its[combo]; i++) {
         unsigned sysc_found = 0;
         unsigned j;
         for (j = 0; j < buf_sizes[combo]; j++) {
            // from http://eternallyconfuzzled.com/arts/jsw_art_rand.aspx
            buf[j] = (uint8_t) ((rand () * (1.0 / (RAND_MAX + 1.0) ) ) * MAX_VALUE);
            distribution[buf[j]]++;
            if (buf[j] == 0x80 && j > 0 && buf[j-1] == 0xcd) {
               printf ("%5u:%6u plaintext cd80 exists\n", i, j);
               syscalls++;
               sysc_found = 1;
               //printf ("0x%02x 0x%02x", buf[j-1], buf[j]);
            }
         } // end for each byte
         // output file
         char filename[256];
         snprintf (filename, sizeof (filename), "randfill-%uB:%u%s.rawshell", buf_sizes[combo], i, sysc_found ? "-cd80" : "");
         FILE* out;
         if ((out = fopen (filename, "w") ) == NULL) {
            printf ("error: couldn't open file %s\n", filename);
            exit (0);
         }
         if (fwrite (buf, sizeof (uint8_t), buf_sizes[combo], out) != buf_sizes[combo]) {
            printf ("error: didn't write properly to file %s\n", filename);
            exit (0);
         }
         fclose (out);
      } // end for each it (iteration to generate)
   } // end for each buf_size:num to generate combo
   
   // do stats to verify
   unsigned totBytes = 0;
   for (combo = 0; combo < combos; combo++) {
      totBytes += buf_sizes[combo] * buf_its[combo];
   }
   // there are n-1 byte pairs for every n length buffer
   unsigned totBytePairs = totBytes;
   for (combo = 0; combo < combos; combo++) {
      totBytePairs -= buf_its[combo];
   }
   unsigned test = 0;
   float syscall_rate = ((float) syscalls)/((float) totBytePairs) * 100.0;
   float syscall_rate_th = 0.001526; // (1/256 * 1/256) * 100
   printf ("There were %u plan text syscalls or %f percent, %.02f perc of theoretical (%f)\n", syscalls, syscall_rate, syscall_rate/syscall_rate_th*100.0, syscall_rate_th);
   printf ("Distribution checker, if any beyond threshold, printed here: ", (int) totBytes/MAX_VALUE);
   for (i = 0; i < MAX_VALUE; i++) {
      //printf (" %d", distribution[i]);
      // find the difference from the theoretical number of occurences that should have happened
      distribution[i] = abs (distribution[i] - ((int) totBytes/MAX_VALUE) );
      // relate this difference in terms of the number of bytes generated
      float percent_diff = (float) distribution[i] / (float) totBytes * 100.0;
      // see if we passed a threshold of value differences from actual to theoretical
      if (percent_diff > PERC_THRESHOLD) {
         printf ("%d:%f", distribution[i], percent_diff);
         test = 1;
      }
      
   }
   if (!test) {
      printf ("None found, entire output is collectively uniformly random");
   }
   printf ("\n");
   
   printf ("Finished, exiting\n");
   /*for (it = 0; it < 3; it++) {
      printf ("For it:%u. There were %u buffers (%f percent) that had a cd80 in them. It would take %u B (%f hr) to test them\n", it, buffersInvolved[it], ((float) buffersInvolved[it])/((float) (ITERATIONS*10/(10*it+1))) * 100.0, bytesInvolved[it], (float) bytesInvolved[it] / 60.0 / 60.0);
   }*/
   
   return 0;
} // end fn main
   

#endif
// end randomFillGenerator.c
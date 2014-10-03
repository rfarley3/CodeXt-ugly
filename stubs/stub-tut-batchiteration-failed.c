#include <stdio.h>
#include <string.h>
//#include "s2e.h"
#include "/home/s2e/s2e/dasos/s2e/s2e/guest/include/s2e.h"  // custom s2e
//#include "/home/s2e/s2e/s2e/guest/include/s2e.h"            // untouched s2e

int main (void) {
   char buf[256];
   memset (buf, '\0', sizeof (buf) );
   unsigned int given_low = 0;
   unsigned int given_high = 20;
   unsigned int symb;
  
   snprintf (buf, sizeof (buf), "Running Modifed S2E Tutorial1 (for Iteration)\n");
   s2e_message (buf);
   printf ("%s\n", buf);

   
   unsigned int maxforks = 10;
   unsigned int batches = given_high / maxforks;
   unsigned int batch;
   for (batch = 0; batch <= batches; batch++) {
      unsigned int batch_low = (batch * maxforks) + given_low;
      unsigned int batch_high = ((batch + 1) * maxforks) + given_low - 1;
      batch_high > given_high ? given_high : batch_high;
      snprintf (buf, sizeof (buf), "<< Doing batch %u of %u, each with %u forks, batch_low: %u, batch_high: %u", batch, batches, maxforks, batch_low, batch_high);
      s2e_warning (buf);
      printf ("%s\n", buf);
      
      symb = s2e_dasospreproc_fuzz (batch_low, batch_high);
      if (symb < batch_low || symb > batch_high) {
         snprintf (buf, sizeof (buf), "Error: should not be here, char is not in range: %u<=%u<=%u", batch_low, symb, batch_high);
         s2e_warning (buf);
         printf ("%s\n", buf);
         s2e_kill_state (1, buf);
         return 1;
      }
      
      snprintf (buf, sizeof (buf), "Success: char is in range: %u<=%u<=%u", batch_low, symb, batch_high);
      s2e_warning (buf);
      printf ("%s\n", buf);
      s2e_kill_state (0, buf);
      return 0;
   }

   s2e_kill_state (1, "shouldn't be here");
   return 1;
} // end fn main

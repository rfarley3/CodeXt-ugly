#include <stdio.h>
#include <string.h>
//#include "s2e.h"
#include "/home/s2e/s2e/dasos/s2e/s2e/guest/include/s2e.h"  // custom s2e
//#include "/home/s2e/s2e/s2e/guest/include/s2e.h"            // untouched s2e

int main (void) {
   char buf[256];
   memset (buf, '\0', sizeof (buf) );
   unsigned int given_low = 0;
   unsigned int given_high = 1000;
  
   snprintf (buf, sizeof (buf), "Running Modifed S2E Iterative Forking Stub\n");
   s2e_message (buf);
   printf ("%s\n", buf);

   // static inline unsigned int s2e_dasospreproc_createFork (unsigned int value)
   unsigned int i;
   for (i = given_low; i <= given_high; i++) {
      //symb = s2e_dasospreproc_fuzz (given_low, given_high);
      unsigned int symb = s2e_dasospreproc_createFork (i);
      if (symb != 0xffffffff) {
         if (symb < given_low || symb > given_high) {
            snprintf (buf, sizeof (buf), "Error: should not be here, char is not in range: %02x:%u<=%u<=%u", symb, given_low, symb, given_high);
            s2e_warning (buf);
            printf ("%s\n", buf);
            s2e_kill_state (1, buf);
            return 1;
         }
         
         snprintf (buf, sizeof (buf), "Success: char is in range: %02x<=%02x<=%02x:%u<=%u<=%u", given_low, symb, given_high, given_low, symb, given_high);
         s2e_warning (buf);
         printf ("%s\n", buf);
         s2e_kill_state (0, buf);
         return 0;
      }
      else {
         snprintf (buf, sizeof (buf), "<< Looping fork, currently at %u", i);
         s2e_warning (buf);
         printf ("%s\n", buf);
      }
   }
   
   snprintf (buf, sizeof (buf), "<< Ending state 0");
   s2e_warning (buf);
   printf ("%s\n", buf);
   s2e_kill_state (0, buf);
   return 0;
} // end fn main

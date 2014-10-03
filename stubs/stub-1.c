#include <stdio.h>
#include <string.h>
//#include "s2e.h"
#include "/home/s2e/s2e/dasos/s2e/s2e/guest/include/s2e.h"  // custom s2e
//#include "/home/s2e/s2e/s2e/guest/include/s2e.h"            // untouched s2e

int main (void) {
   char buf[256];
   memset (buf, '\0', sizeof (buf) );
   char given_min;
   char given_max;
   char symb;
  
   given_min = 'a';
   given_max = 'f';

   s2e_enable_forking ();
   //s2e_make_symbolic (&(symb), 1 * sizeof (char), "symb"); 
   symb = s2e_range (given_min, given_max, "symb");
  
   snprintf (buf, sizeof (buf), "Running Modifed S2E Tutorial1 (for Iteration)\n");
   s2e_message (buf);
   printf ("%s\n", buf);

   if (symb < given_min || symb > given_max) {
      s2e_kill_state (1, "should never be here if using s2e_range: out of range, program terminated");
      return 1;
   }
   
   /* something goes here to make it print all possible examples */ {
      s2e_get_example (&(symb), 1 * sizeof (char) );
      snprintf (buf, sizeof (buf), "Char is in range: s2e_get_example:%02x<=%02x<=%02x:%c<=%c<=%c\n", given_min, symb, given_max, given_min, symb, given_max);
      s2e_warning (buf);
      printf ("%s\n", buf);
      s2e_kill_state (0, "Success, in range, program terminated");
      return 0;
   }
   
   
   s2e_kill_state (1, "should never be here, outside of the forloop, program terminated");
   return 1;
} // end fn main

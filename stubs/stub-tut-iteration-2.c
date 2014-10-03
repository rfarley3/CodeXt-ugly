#include <stdio.h>
#include <string.h>
//#include "s2e.h"
#include "/home/s2e/s2e/dasos/s2e/s2e/guest/include/s2e.h"  // custom s2e
//#include "/home/s2e/s2e/s2e/guest/include/s2e.h"            // untouched s2e

int main (void) {
   char buf[256];
   memset (buf, '\0', sizeof (buf) );
   char given_low = 'a';
   char given_high = 'j';
   char symb;
   //char i;
  
   snprintf (buf, sizeof (buf), "Running Modifed S2E Tutorial1 (for Iteration)\n");
   s2e_message (buf);
   printf ("%s\n", buf);

   //s2e_disable_all_apic_interrupts();  // make faster
   //s2e_enable_forking ();
   //s2e_make_symbolic (&(symb), 1 * sizeof (char), "symb"); 
   symb = s2e_dasospreproc_fuzz (given_low, given_high);
   if (symb < given_low || symb > given_high) {
      snprintf (buf, sizeof (buf), "Error: should not be here, char is not in range: %02x<=%02x<=%02x:%c<=%c<=%c", given_low, symb, given_high, given_low, symb, given_high);
      s2e_warning (buf);
      printf ("%s\n", buf);
      //s2e_dasospreproc_fuzz_kill_state ();
      s2e_kill_state (1, buf);
      return 1;
   }
   
   /* something goes here to make it print all possible examples */ //{
      //s2e_get_example (&(symb), 1 * sizeof (char) );
      snprintf (buf, sizeof (buf), "Success: char is in range: %02x<=%02x<=%02x:%c<=%c<=%c", given_low, symb, given_high, given_low, symb, given_high);
      s2e_warning (buf);
      printf ("%s\n", buf);
      //s2e_dasospreproc_fuzz_kill_state ();
      s2e_kill_state (0, buf);
      return 0;
   //}
   
   
   s2e_kill_state (1, "should never be here, outside of the forloop, program terminated");
   return 1;
} // end fn main

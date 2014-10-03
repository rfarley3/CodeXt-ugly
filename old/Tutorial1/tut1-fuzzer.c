#include <stdio.h>
#include <string.h>
//#include "s2e.h"
#include "/home/s2e/s2e/dasos/s2e/s2e/guest/include/s2e.h"  // custom s2e
//#include "/home/s2e/s2e/s2e/guest/include/s2e.h"            // untouched s2e

int main (void) {
   char buf[256];
   memset (buf, '\0', sizeof (buf) );
   unsigned int static_var = 3;
   unsigned int symbolic_var = 99;
  
   // for symbolic:
   //s2e_disable_all_apic_interrupts();  // make faster
   s2e_enable_forking ();               // Enable forking on symbolic conditions.
   //s2e_make_symbolic (&(symbolic_var), sizeof (symbolic_var), "symbolic_var");
   snprintf (buf, sizeof (buf), "Running Fuzzer Stub, symbolic_var@0x%08x=%02u, is size %u\n", &symbolic_var, symbolic_var, sizeof (symbolic_var) );
   //s2e_message (buf);
   s2e_warning (buf);
   printf ("%s\n", buf);

   // void s2e_dasospreproc_fuzz (unsigned int* var_addr, unsigned int val_min, unsigned int val_max); sizeof (symbolic_var),
   // the second variable is either not being transferred or it is being fubared when others are read. output the hex to see if parts of it are making it.
   // also consider that it could be a data structure issue, as this is 32b, but the host is 64b
   // s2e_dasospreproc_fuzz ((unsigned int) &symbolic_var, 0, 5);
   symbolic_var = s2e_dasospreproc_fuzz (4, 5); //((unsigned int) &symbolic_var, 1, 5);
   snprintf (buf, sizeof (buf), "symbolic_var@0x%08x=%02u\n", &symbolic_var, symbolic_var);
   //s2e_message (buf);
   s2e_warning (buf);
   printf ("%s\n", buf);
   // fork this state foreach (val_min .. val_max)
   if (symbolic_var == static_var) {
      //s2e_get_example (&(symbolic_var), sizeof (symbolic_var) );
      snprintf (buf, sizeof (buf), "Vars are the same: %02u == %02u\n", symbolic_var, static_var);
      //s2e_message (buf);
      s2e_warning (buf);
      printf ("%s\n", buf);
   }
   else {
      //s2e_get_example (&(symbolic_var), sizeof (symbolic_var) );
      snprintf (buf, sizeof (buf), "Vars are not the same: %02u != %02u\n", symbolic_var, static_var);
      //s2e_message (buf);
      s2e_warning (buf);
      printf ("%s\n", buf);
   }

   s2e_disable_forking ();
   s2e_dasospreproc_fuzz_kill_state (); // just hook into the signal that is emitted
   s2e_kill_state (0, "program terminated");

  return 0;
} // end fn main
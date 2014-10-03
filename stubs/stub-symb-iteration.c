/* stub-symb-iteration.c
 * take an offset, a cstring and its length
 * print all valid chars from cstring[offset] to cstring's end, order irrelevant 
 */

#include <stdio.h>
#include <string.h>
//#include <s2e.h>
// our modified version of s2e.h, remember to modify it, do so within EditedS2EFiles/. and then let the makefile cp -vu as necessary
#include "/home/s2e/s2e/dasos/s2e/s2e/guest/include/s2e.h"  
//#include "/home/s2e/s2e/s2e/guest/include/s2e.h"  // untouched s2e.h

char str[1024] = "abcdefghijklmnopqrstuvwxyz0123456789\0";

int main (int argc, char* argv[]) {
   unsigned int offset; // = 0; // no need to assign the variable
   unsigned int str_len = 10;       // exactly like shell_len
   unsigned int i;
   char buf[1024];

   printf ("Running %s to test symbolic iterations...\n", argv[0]);
   
   /* The guest can enable/disable forking as well as kill states at any point in the code. 
    * When forking is disabled, S2E follows only one branch outcome, even if both outcomes are feasible.
    * */
   s2e_enable_forking ();
   //void s2e_make_symbolic(void* buf, int size, const char* name);
   s2e_make_symbolic (&(offset), 1* sizeof (unsigned int), "offset");
   
   // double check that offset is within length
   if (offset >= str_len) {
      s2e_get_example (&(offset), 1 * sizeof (char) ); // gets the symbolic values that were used which reached this point
      snprintf (buf, sizeof (buf), "Error: out of range s2e_get_example:%u(%04x):\n", offset, offset);
      printf ("%s\n", buf);
      s2e_warning (buf);
      s2e_kill_state (1, buf);
      return 1;
   }

   //for (i = 0; i < str_len; i++) {
      //if (offset == i) {
         s2e_get_example (&(offset), 1 * sizeof (char) ); // gets the symbolic values that were used which reached this point
         snprintf (buf, sizeof (buf), "!! offset (%u): str[%u]:%u:%02x\n", offset, offset, (unsigned int) str[offset], str[offset] & 0xff);
         printf ("%s\n", buf);
         s2e_warning (buf);
         s2e_kill_state (0, buf);
         return 0;
      //}
   //}
         
   s2e_disable_forking ();
   // s2e_disable_forking may turn off forking for all other states yet to need to fork, sort of a first to reach here wins insn
   //s2e_disable_forking(); 
   s2e_kill_state (1, "Error: No match found, this shouldn't happen; exiting, execution complete");
   return 1;
} // end fn main

// end stub-symb-iteration.c

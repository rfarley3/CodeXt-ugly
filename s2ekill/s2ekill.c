#include <stdio.h>
#include <string.h>
//#include "s2e.h"
#include "/home/s2e/s2e/dasos/s2e/s2e/guest/include/s2e.h"  // custom s2e
//#include "/home/s2e/s2e/s2e/guest/include/s2e.h"            // untouched s2e

int main (void) {
   s2e_message ("Running s2ekill: orphan state clean up");
   s2e_warning ("Running s2ekill: orphan state clean up");
   printf ("Running s2ekill: orphan state clean up\n");
   s2e_kill_state (1, "killing orphan");
   return 1;
} // end fn main

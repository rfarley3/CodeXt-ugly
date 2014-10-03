#include <stdio.h>
#include <string.h>
//#include "s2e.h"
//#include "/home/s2e/s2e/dasos/s2e/s2e/guest/include/s2e.h"  // custom s2e
#include "/home/s2e/s2e/s2e/guest/include/s2e.h"            // untouched s2e

int main (void) {
  char buf[32];
  memset (buf, '\0', sizeof (buf) );
  char given;
  char symb;
  // for non-symbolic:
  /*
   char str[3];
   memset (str, '\0', 3);
   printf("Enter two characters: ");
   if (!fgets(str, sizeof(str), stdin))
      return 1;
   symb = str[0];
   given = str[1];
  */
  
  // for symbolic:
  //s2e_disable_all_apic_interrupts();  // make faster
  given = 'a';
  s2e_enable_forking ();               // Enable forking on symbolic conditions.
  s2e_make_symbolic (&(symb), 1 * sizeof (char), "symb"); 
  // saves state
  // forks to creates a new state with symbolic (random) values for str[0] and str[1]
  // note, this means it only created and ran 1 set of symbolic value
  snprintf (buf, sizeof (buf), "Running S2E Tutorial1\n");
  /*s2e_get_example (&(symb), 1 * sizeof (char) ); // gets the symbolic values that were used which reached this point
  snprintf (buf, sizeof (buf), "Running S2E Tutorial1:%02x%02x%c%c:\n", (unsigned char) symb, (unsigned char) given, symb, given);*/
  s2e_message (buf);
  printf ("%s\n", buf);

  if (symb == '\0') {
    printf ("No input char\n");

  } else {
    if (symb >= 'a' && symb <= 'z')
      printf ("Char is lowercase\n");
    else
      printf ("Char is not lowercase\n");

    if (symb >= '0' && symb <= '9')
      printf ("Char is a digit\n");
    else
      printf ("Char is not a digit\n");

    if (symb == given) {
      printf ("Chars are the same: %c == %c\n", symb, given);
      s2e_get_example (&(symb), 1 * sizeof (char) ); // gets the symbolic values that were used which reached this point
      snprintf (buf, sizeof (buf), "s2e_get_example:%02x%02x%c%c:\n", (unsigned char) symb, (unsigned char) given, symb, given);
      s2e_warning (buf);
      printf ("%s\n", buf);
    }
    else
      printf ("Chars are not the same: %c != %c\n", symb, given);
  }

  s2e_disable_forking ();

  s2e_get_example (&(symb), 1 * sizeof (char) ); // gets the symbolic values that were used which reached this point
  snprintf (buf, sizeof (buf), "s2e_get_example:%02x%02x%c%c:\n", (unsigned char) symb, (unsigned char) given, symb, given);
  s2e_warning (buf);
  printf ("%s\n", buf);

  s2e_kill_state (0, "program terminated");

  return 0;
}
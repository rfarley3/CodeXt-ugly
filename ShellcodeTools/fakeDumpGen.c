/* fakeDumpGen.c
 * given a raw shellcode, specified by filename, create a dump to test our system with
 * 
 * To compile:
 * gcc -o fakeDumpGen fakeDumpGen.c ../libDasosfDump.o
 */

#include <stdio.h>
#include "../libDasosf/libDasosfDump.h"
//#include <string.h>

char test[] = "\xeb\x13\x59\x31\xc0\xb0\x04\x31\xdb\x43\x31\xd2"
               "\xb2\x0f\xcd\x80\xb0\x01\x4b\xcd\x80\xe8\xe8\xff"
               "\xff\xff\x48\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72"
               "\x6c\x64\x21\x0a\x0d";

char shellcode[1024];

unsigned int verbose;



unsigned int getInput (char* input, char* in_filename);
unsigned int decodeShell (char* raw, unsigned int* len);
unsigned int storeIntoShell (char* input, unsigned int input_len, struct shellcode* shellcode);
unsigned int makeDumpNulls (struct dasos_forens_dump* dump, struct shellcode* shellcode);


void usage (char* self) {
   printf ("%s -i <input filename> [-t <template dump filename>]? -d <output dump filename>\n", self);
   printf ("e.g. %s -i poly.shell -d poly.dump\n", self);
   exit (1);
} // end fn usage


int main (unsigned int argc, char* argv[]) {
   struct dasos_forens_dump output;  
   struct dasos_forens_dump template;  
   struct shellcode shellcode;

   unsigned int i;
   char input_filename[256];
   char input[1024];
   unsigned int input_len = 0;
   //unsigned int decoded_len = 0;
   unsigned int input_type = 0; // not user set: 0 raw shell, 1 decoded shell
   unsigned int fill_type = 0; // not user set: 0 nulls, 1 random, 2 dump file template
   char template_filename[256];
   memset (template_filename, '\0', sizeof (char) * 256);
   char out_filename[256];
   memset (out_filename, '\0', sizeof (char) * 256);
#ifdef VERB
   verbose = 1;
#else
   verbose = 0;
#endif
   /*if (argc == 1) {
      usage (argv[0]);
   }*/
   for (i = 1; i < argc; i++) {
     if (argv[i][0] != '-' || (i + 1) == argc) {
        printf ("Invalid cmd line arg or not enough args\n");
	usage (argv[0]);
     }
     switch (argv[i][1]) {
       case 'i' :
	  i++;
          input_len = getInput (input, argv[i]);
          strncpy (input_filename, argv[i], 256);
	  break;
       case 't' :
          i++;
          fill_type = 2;
          // read in dump file
          readFileToMem (argv[i], &template);
          strncpy (template_filename, argv[i], 256);
          // strip dump info, output EIP
          //shell = (void *) dump.dump;
          //eip = (unsigned int) (dump.dump) + (512 * sizeof (char) ); // per dump grab, the offset is always 512
          break;
       case 'd' :
	  i++;
	  strncpy (out_filename, argv[i], 256);
	  break;
       default:
	  printf ("Invalid arg\n");
	  usage (argv[0]);
     }
   }
   // default
   if (input_len == 0) {
      sprintf (input_filename, "built-in pre-decoded test shellcode");
      input_len = strlen (test);
      memcpy (input, test, sizeof (char) * input_len);
      input_type = 1;
      //decoded_len = input_len;  // pre-decoded
   }
   // default
   if (out_filename[0] == '\0') {
      sprintf (out_filename, "out_fakeDumpGen.dump");
   }
   if (verbose) {
      printf ("Running %s with input: %s, output: %s\n", argv[0], input_filename, out_filename);
      /*switch (fill_type) {
         case 0 :
            printf ("Using nulls to fill dump file\n");
            break;
         case 1 :
            printf ("Using random to fill dump file\n");
            break;
         case 2 :
            printf ("Using a template dump file: %s\n", template_filename);
            break;
         default :
            printf ("Error with template dump file type, shouldn't see this\n");
            exit (1);
            break;
      }*/
   }


   if (input_type == 0) {
      printf ("Decoding the shell into the snapshot that the forensic module would capture\n");
      decodeShell (input, &input_len);
   }
   // at this point the input should be the decoded shell
   if (storeIntoShell (input, input_len, &shellcode) == 0) {
      printf ("Error creating shellcode\n");
      exit (1);
   }
   
   printf ("\nUsing this snapshot of the shellcode: (EIP is 0x%08x)\n", shellcode.eip);
   memset (output.preamble, '\0', sizeof (char) * 6);
   output.start_addr = 0;
   output.num_bytes = 0;
   memset (&(output.deets), '\0', sizeof (struct dasos_forens_deets) );
   memset (output.dump, '\0', sizeof (char) * DUMP_SIZE);
   printShellcode (output, shellcode);

   // generate dump
   switch (fill_type) {
      case 0 :
         printf ("Using nulls to fill dump file\n");
         makeDumpNulls (&output, &shellcode);
         break;
      case 1 :
         printf ("Using random to fill dump file\n");
         //makeDumpRand
         break;
      case 2 :
         printf ("Using a template dump file: %s\n", template_filename);
         //makeDumpTemplate
         break;
      default :
         printf ("Error with template dump file type, shouldn't see this\n");
         exit (1);
         break;
   }

   printf ("\nHere is the dump:\n");
   printDump (output);
   
   printf ("Exiting\n");
   return 0;
} // end fn main


unsigned int getInput (char* input, char* in_filename) {
   FILE* IN_FILE;
   unsigned int len = 0;

   if ((IN_FILE = fopen (in_filename, "r") ) == NULL) {
      printf ("Invalid file\n");
      exit (1);
   }
   len = fread(input, sizeof (char), 1024, IN_FILE);
   fclose (IN_FILE);
   return len;
}


unsigned int decodeShell (char* raw, unsigned int* len) {
   unsigned int raw_len = *len;
   return 0;
} // end fn decodeShell


unsigned int storeIntoShell (char* input, unsigned int input_len, struct shellcode* shellcode) {
   unsigned int i;

   shellcode->len = input_len;
   shellcode->addr = 0;
   memcpy (shellcode->shell, input, sizeof (char) * shellcode->len);
   for (i = 0; i < shellcode->len; i++) {
      if ((i + 1) < shellcode->len) {
         unsigned int byte1 = (unsigned int) ((char *) (shellcode->shell) )[i] & 0x000000ff;
         unsigned int byte2 = (unsigned int) ((char *) (shellcode->shell) )[i + 1] & 0x000000ff;
         if ((byte1 == 0xcd && byte2 == 0x80) ||    // int 80 / interrupt / syscal
             (byte1 == 0x0f && byte2 == 0x34) ) {   // sysenter
            shellcode->eip = shellcode->addr + i + 2;
            return 1;
         }
      }
   }
   return 0;
} // end fn storeIntoShell


unsigned int makeDumpNulls (struct dasos_forens_dump* dump, struct shellcode* shellcode) {

   //setPreamble (dump->preamble); //char[6] fill as as wanted
   memset ((dump->preamble), '\0', sizeof (char) * 6);
   dump->start_addr = 0;
   shellcode->addr = 512 - shellcode->eip;
   shellcode->eip = 512;
   dump->deets.eip = shellcode->eip;
   // fill in the other deets
   dump->num_bytes = DUMP_SIZE;
   memset (&(dump->dump), '\0', sizeof (char) * DUMP_SIZE);
   memcpy (&(dump->dump[(shellcode->addr - dump->start_addr)]), shellcode->shell, sizeof (char) * shellcode->len);

   return 0;
} // end fn makeDumpNulls

// makeDumpRand 
/*for (i = 0; i < haystack.num_bytes; i++) {
   //http://eternallyconfuzzled.com/arts/jsw_art_rand.aspx
   haystack.dump[i] = (char) ((rand () * (1.0 / (RAND_MAX + 1.0) ) ) * 256);
}*/


// end fakeDumpGen.c

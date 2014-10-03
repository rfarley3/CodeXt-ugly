#ifndef _shellcode_wrapper_c
#define _shellcode_wrapper_c
/* shellcode-wrapper.c
 * given a raw shellcode, specified by filename, jump to array as if it were a fn
 * 
 * To compile:
 * gcc -fno-stack-protector -z execstack -o shellcode-wrapper shellcode-wrapper.c libDasosfDump.o
 * other possible things that might need to be disabled: -D_FORTIFY_SOURCE=0
 * in general visit this link: http://smashthestack.org/viewtopic.php?id=388
 * 
 * To run:
 * ./shellcode-wrapper [-d <dump file from our kernel extension> | -f <filename of shellcode; if no -f flag, then built-in hello world shell is used>] -o <offset within shellcode to begin execution>
 * e.g.
 * ./shellcode-wrapper -f ../../dumps/handcut.shell -o 2
 * ./shellcode-wrapper -d ../../dumps/ghttpd-4f3b24c4\:786.dump -o 1
 */

#include <stdio.h>
#include <signal.h>
#include "../libDasosf/libDasosfDump.h"
#ifdef SYMB
#include "/home/s2e/s2e/dasos/s2e/s2e/guest/include/s2e.h" // modified s2e.h
#endif

#define INCLUDE_EIP 1
#define INCLUDE_SYSC 1

typedef enum {HW, RAW, DUMP} Source_type;

struct Options {
   bool verbose;
   //void (*shell) ();
   struct shellcode shellcode; // .shell[], .len, .addr (start), .eip, .syscall
   struct dasos_forens_dump dump; // .start_addr, .num_bytes, .deets, .dump[]
   // .deets = .syscall, .eip, ...
   bool disasm;
   bool print;
   bool file_out;
   bool exec_shellcode;
   
   Source_type source_type;
   bool eip_given_incl;
   bool eip_needed;
   bool converted;
   
   uint offset;
   uint cases;
   bool output_raw;
   char out_filename[256];
   Fill_type fill_type;
   uint disasm_start;
   uint disasm_len;
};


void execShellcode (struct shellcode* s, uint f, uint c, uint eip_known);
void normalizeShellcode (struct shellcode* s);
#ifdef SYMB
static void signal_handler (int sig);
#endif
void usage (char* self);
void initOpts (struct Options* o);
void getOpts (int argc, char* argv[], struct Options* o);
void verifyOpts (struct Options* o);


char hello[] = "\xeb\x13\x59\x31\xc0\xb0\x04\x31\xdb\x43\x31\xd2\xb2\x0f\xcd\x80"
               "\xb0\x01\x4b\xcd\x80\xe8\xe8\xff\xff\xff\x48\x65\x6c\x6c\x6f\x2c"
               "\x20\x77\x6f\x72\x6c\x64\x21\x0a\x0d";


int main (int argc, char* argv[]) {
   struct Options opts;
   
   initDasosfDump (&(opts.dump), &(opts.shellcode) );
   initOpts (&opts);
   getOpts (argc, argv, &opts);
   verifyOpts (&opts);
   if (opts.verbose) {
      printf ("<< Running with options: ...fill this in...\n");
   }
   
   #ifdef SYMB
   signal (SIGSEGV, signal_handler);
   signal (SIGILL, signal_handler);
   #endif

   if (opts.disasm) {
      printf ("<< Requesting disasm out\n");
      if (opts.source_type == HW || opts.source_type == RAW) {
         printf ("<< From raw input\n");
         printDisasmRange ((byte_t*) &(opts.shellcode.shell[opts.disasm_start]), opts.disasm_len);
      }
      else {
         printf ("<< From dump input\n");
         printDisasmRange ((byte_t*) &(opts.dump.dump[opts.disasm_start]), opts.disasm_len);
      }
   }
   
   
   if (opts.print) {
      printf ("<< Requesting print out\n");
      if (opts.source_type == HW || opts.source_type == RAW) {
         printf ("<< From raw input\n");
         printShell (opts.shellcode);
      }
      else {
         struct tm* tm_tmp;
         struct timeval local_ktv;
         printf ("<< From dump input\n");
         // this allows the linux struct to be typeset into local OS version (and allow that OS's localtime to function properly
         local_ktv.tv_sec = opts.dump.deets.ktv.tv_sec;
         tm_tmp = localtime ( &(local_ktv.tv_sec) ); //dump.deets.ktv.tv_sec) );
         printf ("<< Dump of %s (%d), check_no %d captured at %4d/%02d/%02d %02d:%02d:%02d.%03d, issued sycall %u from eip 0x%08x, secret: %u true_secret: %u\n", opts.dump.deets.proc_name, opts.dump.deets.pid, opts.dump.deets.check_no, tm_tmp->tm_year+1900, tm_tmp->tm_mon, tm_tmp->tm_mday, tm_tmp->tm_hour, tm_tmp->tm_min, tm_tmp->tm_sec, opts.dump.deets.ktv.tv_usec/1000, opts.dump.deets.syscall, opts.dump.deets.eip, opts.dump.deets.secret, opts.dump.deets.true_secret);
         // print the memory segment of the dump using a format similar to gdb's memory view window
         printDump (opts.dump);
      }
   }
   
   
   if (opts.file_out) {
      // if output raw shellcode file
      if (opts.output_raw) {
         printf ("<< Requesting raw output\n");
         if (opts.source_type == DUMP) {
            printf ("<< From dump input\n");
            if (!opts.converted) {
               storeDumpIntoShellcode (&(opts.dump), &(opts.shellcode) );
               opts.converted = true;
               // verifyOpts?
            }
         }
         else {
            printf ("<< From raw input. Hmmm, did you mean to input a raw shellcode file only to output it again? Continuing.\n");
         }
         writeShellcodeToFile (opts.shellcode, opts.out_filename);
      }
      // else output dump file
      else {
         printf ("<< Requesting dump output\n");
         if (opts.source_type == HW || opts.source_type == RAW) {
            printf ("<< From raw input\n");
            if (!opts.converted) {
               /*if (!opts.eip_given_incl || opts.eip_needed) {
                  printf ("Need to normalize shellcode\n");
                  // if we only have raw shellcode (o->shellcode) then there is some missing information that we need
                  normalizeShellcode (&(opts.shellcode) );
                  // should this make a new shellcode? and then output to a new dump?
               }*/
               // add in the fill
               storeShellcodeIntoDump (&(opts.shellcode), &(opts.dump), opts.fill_type, !opts.eip_needed);
               opts.converted = true;
            }
         }
         else {
            printf ("<< From dump input. Hmmm, did you mean to input a dump file only to output it again? Continuing.\n");
         }
         writeDumpToFile (&(opts.dump), opts.out_filename);
      }
   }
   
   
   if (opts.exec_shellcode) {
      printf ("<< Requesting execution\n");
      // if we need to make up some filler
      if ((opts.source_type == HW || opts.source_type == RAW) && opts.fill_type != NONE) {
         printf ("<< From raw input but specified filler, make artificial dump to executed\n");
         // add in the fill
         if (!opts.converted) {
            storeShellcodeIntoDump (&(opts.shellcode), &(opts.dump), opts.fill_type, !opts.eip_needed);
            opts.converted = true;
         }
         // restore back to what execShellcode is looking for
         storeDumpIntoShellcode (&(opts.dump), &(opts.shellcode) );
         // verifyOpts?
      }
      else if (opts.source_type == DUMP && !opts.converted) {
         storeDumpIntoShellcode (&(opts.dump), &(opts.shellcode) );
         opts.converted = true;
         // verifyOpts?
      }
      execShellcode (&(opts.shellcode), opts.offset, opts.cases, !opts.eip_needed);
   }
   
   #ifdef SYMB
   s2e_kill_state (0, "<< Ending state");
   #endif
   return 0;
} // end fn main


void execShellcode (struct shellcode* s, uint f, uint c, bool eip_known) {
   char buf[1024];
   maddr_h curr_offset; //NOTE that this is not maddr_d bc it needs the hosts setup, there may need to be a conversion here is the host is 64b and the dumps are not
   
   snprintf (buf, sizeof (buf), "<< Within execShellcode with params f: %u, c: %u, eip_known: %s\n", f, c, (eip_known ? "yes" : "no") );
   #ifdef SYMB
   s2e_message (buf);
   #else
   printMemRange (s->shell, s->len);
   #endif
   
   #ifdef SYMB_OFFSET
   unsigned int i;
   for (i = f; i < (f + c); i++) {
      curr_offset = (maddr_h) s2e_dasospreproc_createFork (i);
   #else
      curr_offset = f;
   {
   #endif
      if (curr_offset != 0xffffffff) {
         // double check that offset is within length
         if (curr_offset > s->len) {
            snprintf (buf, sizeof (buf), "!! Error: invalid offset %u", curr_offset);
            #ifdef SYMB
            s2e_kill_state (1, buf);
            #endif
            printf ("%s\n", buf);
            exit (1);
         }
         void (*shell) () = (void *) &(s->shell[0]);
         //unsigned int shell_addr = (unsigned int) shell;
         
         maddr_h eip = eip_known ? (maddr_h) shell + s->eip : EIP_UNKNOWN;
         // eip of EIP_UNKNOWN ie 0 means that we don't know it
         // s->syscall of SYSC_UNKNOWN ie 1024 means that we don't know it
         snprintf (buf, sizeof (buf), "<< About to call dasospreproc_init with shell: 0x%08x (offset of %d not yet applied), shell_len: %u, eip: 0x%08x\n", (uint) shell, curr_offset, s->len, eip);
         #ifdef SYMB
         s2e_message (buf);
         //snprintf (buf, 1024, "len addr 0x%08x, u: %u, umasked: %u, d: %d, dmasked: %d, hex: %08x", &shellcode.len, shellcode.len, (shellcode.len & 0xffffffff), shellcode.len, (shellcode.len & 0xffffffff), shellcode.len);
         //s2e_message (buf);
         s2e_dasospreproc_init ((uint) shell, s->len, eip, s->syscall);
         #endif
         shell += curr_offset;

         printf ("<< Calling shell: 0x%08x (adjusted by offset of %d), of len: %u with eip: 0x%08x (%u) and syscall: %u\n", (uint) shell, curr_offset, s->len, eip, eip - (maddr_h) shell, s->syscall);
         shell ();
         
         #ifdef SYMB
         s2e_kill_state (1, "!! Error: Shouldn't be here");
         #endif
         exit (1);
      }
      else {
         #ifdef SYMB
         snprintf (buf, sizeof (buf), "<< Looping fork, currently at %u", i);
         s2e_warning (buf);
         #endif
      }
   }
   #ifdef SYMB
   s2e_dasospreproc_fini ();
   s2e_kill_state (0, "<< Ending state 0");
   #endif
   return;
} // end fn execShellcode


// TODO
void normalizeShellcode (struct shellcode* s) {
   // try to ascertain: 
   //    1) eip; and, 
   //    2) syscall.
   // to find these, decode raw shellcode into equivalent of what dasosf.mod would capture; ie simulate execution until first system call is seen and then use that snapshot to build the output dump
   // eip is needed to help s2e find the true shellcode
   // syscall is nice as it helps eliminate false positives
   return;
} // end fn normalizeShellcode











void usage (char* self) {
   printf ("%s:\n", self);
   printf ("   This program allows users to interact with dumps from the forensics module DasosFDump\n"
           "   Primarily it treats a byte array as a callable function, so that you can load in shellcode and execute it. It is essentially a wrapper for shellcode.\n"
           "   Very specifically it:\n"
           "      -Loads a byte array into memory, from either raw shellcode or a dasosfdump\n"
           "      -And then does any combination of the following:\n"
           "         -Prints it in human readable form\n"
           "         -Prints a subset of the byte array disasmbled\n"
           "         -Executes it at any offset\n"
           "         -Outputs it to file (converting raw->dump or dump->raw).\n"
           "      -It also has built-in signal catchers to ensure that it kills itself on bad instructions\n"
           "\n"
           "   In symbolic mode (via S2E) this program executes the input at various offsets in coordination with the DasosPreproc module in order to find the logical start of byte code within the byte array that leads to a system call. If additional information is known, then system calls are filtered by EIP and EAX (sysc number). To do this an offset is given (f) and a number of cases (c) is specified. The wrapper uses state 0 to iteratively fork a state for every case (i = f .. f+c). Each state calls the byte array at its offset i. Before the byte array is called, DasosPreproc is told the memory range to monitor (the byte array) and optionally the EIP and system call number to look for. Once called, processing resides within the DasosPreproc module, further documentation can be found within its code, however all paths should result in the module killing the state (success or failure). If at any time processing returns to the wrapper due to illegal instructions or otherwise, then that state is killed. Once the forked state is killed, state 0 iterates to the next i and forks for it.\n"
           "\n"
           "   Arguments:\n"
           "      --help               This output\n"
           "      -i <filename>        Input file to load into memory. Can be either raw shellcode or a dasosfdump struct\n"
           "                              Exclude this to use built-in helloworld scode\n"
           "                              Type is determined by looking for a special header that exists in dumps\n"
           "      -x                   eXecute byte array.\n"
           "      -p                   Print the input to screen in human readable form\n"
           "      -d <uint x>,<uint y> Disassemble input into human readable form from arr[x] to arr[x+y]\n"
           "      -o <filename> [-r]   Output the input, converting types as necessary\n"
           "                              Default is as a dump struct, but -r specifies raw shellcode\n"
           "                              File extension is done automatically\n"
           "      -t <n|r>             Type of fill: n = nulls; r = random\n"
           "                              Use this if you input raw shellcode and either want to exec or output it as a dump\n"
           "                              The dump will be 1024B, and the default fill is nulls\n"
           "                              If the EIP is known, then it will be at the 512th byte\n"
           "                              Else, the shellcode will start at the 512th byte\n"
           "      -e <uint>            EIP 0 .. byte array length, use this if you input raw shellcode.\n"
           "                              Not an actual address, but the index/offset within the byte array\n"
           "      -f <uint>            oFfset 0 .. byte array length, use this if you are executing the scode\n"
           "                              Default is 0\n"
           "                              Specifies the starting offset to call within shell\n"
           "      -c <uint>            Cases to do offset .. (offset + cases), use this if in S2E symbolic mode\n"
           "                              Default is byte array length - offset\n"
           "\n"
   );
   // TODO add a (-n) normalize option to preprocess a given shellcode until the 1st syscall to make an image that matches what the DasosFDump kern mod captures
   // TODO add a (-s <int>) syscall call option so the user can specify the system call on the command line for a rawshell input
   // TODO add cut/slice start and end options so the user can specify which slice of a dump to use when converting to a rawshell (ie you only want bytes 400-600)
   printf ("   Examples:\n"
           "      Print raw shell file (and don't execute): -i x.rawshell -p\n"
           "      Print dump file (and don't execute): -i x.dump -p\n"
           "      Output builtin helloworld to dump file: -t n -e 16 -o helloworld\n"
           "      Output builtin helloworld to raw shell file: -e 16 -o helloworld -r\n"
           "      Convert rawshell to dump with null filler: -i x.rawshell -t n -o x\n"
           "      Convert dump to rawshell: -i x.dump -o x -r\n"
           "      Execute rawshell with rand filler and known eip of 41: -i x.rawshell -e 41 -t r -x\n"
           "      Execute dump: -i x.dump -x\n"
           "\n"
   );
   #ifdef SYMB
   s2e_kill_state (1, "Invalid usage");
   #endif
   exit (1);
} // end fn usage


#ifdef SYMB
static void signal_handler (int sig) {
   /*switch (sig) {
    case SIGSEGV:
    case SIGILL:*/
   char buf[256];
   snprintf (buf, sizeof (buf), "!! Caught fatal signal: %d", sig);
   printf ("%s\n", buf);
   s2e_kill_state (1, buf);
   abort ();
   /*break;
   }*/
} // end fn signal_handler
#endif


void initOpts (struct Options* o) {
   o->verbose = false;
   // init the exec options to builtin helloworld scode
   o->shellcode.addr = (maddr_d) hello;
   if (INCLUDE_EIP) {
      o->shellcode.eip = 16; //(unsigned int) hello + 16 * sizeof (char);
      o->eip_given_incl = false;
      o->eip_needed = false;
   }
   else {
      o->shellcode.eip = EIP_UNKNOWN;
      o->eip_given_incl = false;
      o->eip_needed = true;
   }
   if (INCLUDE_SYSC) {
      o->shellcode.syscall = 4;
   }
   else {
      o->shellcode.syscall = SYSC_UNKNOWN;
   }
   o->shellcode.len = 41;
   o->source_type = HW;
   o->converted = false;
   o->offset = 0;
   o->cases = o->shellcode.len;
   memcpy (o->shellcode.shell, hello, o->shellcode.len / sizeof (byte_t) );
   // end of builtin helloworld scode specific options

   o->disasm = false;
   o->print = false;
   o->file_out = false;
   o->exec_shellcode = false;
   
   o->disasm_start = 0;
   o->disasm_len = 0;
   
   o->output_raw = false;
   o->fill_type = NONE;
   memset (o->out_filename, '\0', sizeof (o->out_filename) );
   return;
} // end fn initOpts


void getOpts (int argc, char* argv[], struct Options* o) {
   unsigned int i;
   
   #ifdef SYMB_OFFSET
      #ifndef SYMB
      #error You defined SYMB_OFFSET, but forgot to define its dependent SYMB
      #endif
   #endif
   
   for (i = 1; i < argc; i++) {
      if (argv[i][0] != '-') {
         printf ("Error: invalid cmd line arg (%u:%s)\n", i, argv[i]);
         usage (argv[0]);
      }
      switch (argv[i][1]) {
         case 'v' :
            o->verbose = true;
            break;
         case 'r' :
            o->output_raw = true;
            break;
         case 'p' :
            o->print = true;
            break;
         case 'x' :
            o->exec_shellcode = true;
            break;
         case '-' :
            // arg is --? probably --help
            usage (argv[0]);
            break;
         default :
            //printf ("CLA: %u:%s\n", i, argv[i]);
            if ((i + 1) == argc) {
               printf ("!! Error: invalid cmd line, not enough args\n");
               usage (argv[0]);
            }
            switch (argv[i][1]) {
               case 'd' :
                  i++;
                  o->disasm = true;
                  char* tmp = argv[i];
                  tmp = strtok (tmp, ",");
                  int tmp_in = atoi (tmp);
                  o->disasm_start = (unsigned int) tmp_in;
                  tmp = strtok (NULL, "\0");
                  tmp_in = atoi (tmp);
                  o->disasm_len = (unsigned int) tmp_in;
                  break;
               case 't' :
                  i++;
                  if (argv[i][0] == 'n') {
                     o->fill_type = NULLS;
                  }
                  else if (argv[i][0] == 'r') {
                     o->fill_type = RANDOM;
                  }
                  else {
                     printf ("!! Error: invalid fill type\n");
                     usage (argv[0]);
                  }
                  break;
               case 'i' :
                  i++;
                  // undo any source_type HW stuff
                  memset (o->shellcode.shell, '\0', o->shellcode.len / sizeof (uint8_t) );
                  o->shellcode.addr = 0;
                  o->shellcode.len = 0;
                  o->shellcode.syscall = SYSC_UNKNOWN;
                  if (!o->eip_given_incl) {
                     o->shellcode.eip = EIP_UNKNOWN;
                     o->eip_needed = true;
                  }
                  FILE* INP;
                  if ((INP = fopen (argv[i], "r") ) == NULL) {
                     printf ("!! Error: invalid file\n");
                     exit (1);
                  }
                  char test_inp[DASOSFDUMP_PREAMBLE_LEN];
                  unsigned int read = 0;
                  read = fread (test_inp, sizeof (char), DASOSFDUMP_PREAMBLE_LEN, INP);
                  fclose (INP);
                  if (isThisADasosfDump (test_inp, DASOSFDUMP_PREAMBLE_LEN) ) {
                     o->source_type = DUMP;
                     // reread file using libDasosfDump
                     readFileToDump (argv[i], &(o->dump) );
                     // conversion to shellcode from dump is straight forward, do it here to make life easier
                     storeDumpIntoShellcode (&(o->dump), &(o->shellcode) );
                     o->converted = true;
                     if (o->dump.deets.eip != EIP_UNKNOWN) {
                        o->eip_needed = false;
                     }
                     // default the number of cases to shellcode length - offset
                     o->cases = o->dump.num_bytes - o->offset;
                  }
                  else {
                     o->source_type = RAW;
                     unsigned int temp_eip;
                     if (o->eip_given_incl) {
                        temp_eip = o->shellcode.eip;
                     }
                     readFileToShell (argv[i], &(o->shellcode) );
                     o->shellcode.eip = o->eip_given_incl ? temp_eip : EIP_UNKNOWN;
                     // o->fill_type none is the default
                     // default the number of cases to shellcode length - offset
                     o->cases = o->shellcode.len - o->offset;
                  }
                  break;
               case 'e' :
                  i++;
                  // manually set the eip, this should only be done if shellcode is raw
                  int eip_in = atoi (argv[i]);
                  o->shellcode.eip = (maddr_d) eip_in;
                  o->eip_given_incl = true;
                  o->eip_needed = false;
                  break;
               case 'o' :
                  i++;
                  strncpy (o->out_filename, argv[i], sizeof (o->out_filename) / sizeof (char) );
                  o->file_out = true;
                  break;
               case 'f' :
                  i++;
                  int offset_in = atoi (argv[i]);
                  o->offset = (unsigned int) offset_in;
                  break;
               case 'c' :
                  #ifndef SYMB_OFFSET 
                  printf ("!! Warning: offset is concrete, ignoring cases argument\n");
                  #else
                  i++;
                  int cases_in = atoi (argv[i]);
                  o->cases = (unsigned int) cases_in;
                  if (o->cases == 0) {
                     printf ("!! Error: cases must be > 0\n");
                     usage (argv[0]);
                  }
                  #endif
                  break;
               default:
                  printf ("!! Error: invalid arg\n");
                  usage (argv[0]);
            } // end switch cla of 2 argv
      } // end switch cla of only 1 argv
   } // end for each cla
   return;
} // end fn getOpts


void verifyOpts (struct Options* o) {
   if (o->file_out && o->out_filename[0] == '\0') {
      strncpy (o->out_filename, "sw-output\0", sizeof (o->out_filename) );
      // file extension is added by libDasosfDump
      printf ("!! Warning: making an output file without being told a filename via -o; defaulting to %s\n", o->out_filename);
      //usage (argv[0]);
   }
   
   if (o->file_out && !o->output_raw && o->fill_type == NONE) {
      printf ("!! Warning: dump output specified, but no fill type specified, using nulls\n");
      o->fill_type = NULLS;
   }
   
   if (o->eip_given_incl && o->source_type == DUMP) {
      // the use gave a specific eip, but the input was a dump file, this may cause problems
      printf ("!! Warning: specified eip while using dump input, this shouldn't be necessary\n");
   }
   
   if ((o->source_type == HW || o->source_type == RAW) || (o->source_type == DUMP && o->converted) ) {
      if (!o->eip_needed && o->shellcode.eip >= o->shellcode.len) {
         printf ("!! Error: eip is out of shellcode range\n");
         exit (1);
      }
      if ((o->cases + o->offset) > o->shellcode.len) {
         o->cases = o->shellcode.len - o->offset;
         printf ("!! Warning: given cases exceeds possible, setting to maximum: %u\n", o->cases);
      }
      if (o->disasm && (o->disasm_start + o->disasm_len) > o->shellcode.len) {
         printf ("!! Error: disasm range is out of shellcode range\n");
         exit (1);
      }
   }
   
   if (o->eip_given_incl && o->shellcode.eip == EIP_UNKNOWN) {
      printf ("!! Warning: given eip is same as eip_unknown value, program will assume no eip given\n");
   }
   
   if (!o->disasm && !o->print && !o->file_out && !o->exec_shellcode) {
      if (o->source_type == HW) {
         printf ("!! Warning: no mode given and no input specified, what's the point?\n");
      }
   }

   return;
} // end fn verifyOpts

#endif
// end shellcode-wrapper.c
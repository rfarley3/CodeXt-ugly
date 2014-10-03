#ifndef _randfill_c
#define _randfull_c
/* randomFillTester.c
 * Produce 10,000   1K buffers
 *          1,000  10K
 *            100 100K
 * See if have any cd80, if so output them to file and see if any have eax < 512 upon that syscall from any offset
 */

#include <stdio.h>
#include <signal.h>
#include "../libDasosf/libDasosfDump.h"

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
   bool normalize;
   bool exec_shellcode;
   bool multi_syscalls;
   
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

struct Signal {
   //unsigned int value;
   //char action[16];
   char comment[256];
};

struct Signal signals[32];

void execShellcode (struct shellcode* s, uint f, uint c, uint eip_known, bool enable_multiple);
void normalizeShellcode (struct shellcode* s, uint f);
#ifdef SYMB
void setSignalHandlers ();
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
   setSignalHandlers ();
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
   

   if (opts.normalize) {
      printf ("<< Requesting normalization/preprocessing\n");
      if (!(opts.source_type == HW || opts.source_type == RAW) ) {
         printf ("!! Error: can't normalize a dump, must be raw shellcode\n");
         return 1;
      }
      normalizeShellcode (&(opts.shellcode), opts.offset);
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
      execShellcode (&(opts.shellcode), opts.offset, opts.cases, !opts.eip_needed, opts.multi_syscalls);
   }
   
   #ifdef SYMB
   s2e_kill_state (0, "<< Ending state");
   #endif
   return 0;
} // end fn main


void execShellcode (struct shellcode* s, uint f, uint c, bool eip_known, bool enable_multiple) {
   char buf[1024];
   maddr_h curr_offset; //NOTE that this is not maddr_d bc it needs the hosts setup, there may need to be a conversion here is the host is 64b and the dumps are not
   
   snprintf (buf, sizeof (buf), "<< Within execShellcode with params f: %u, c: %u, eip_known: %s, enable_multiple_syscalls: %s\n", f, c, (eip_known ? "yes" : "no"), (enable_multiple ? "yes" : "no") );
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
         if (enable_multiple) {
            s2e_dasospreproc_enableMultiple ();
         }
         s2e_dasospreproc_init ((uint) shell, s->len, eip, s->syscall);
         #endif
         shell += curr_offset;

         printf ("<< Calling shell: 0x%08x (adjusted by offset of %u), of len: %u with eip: 0x%08x (%u) and syscall: %u\n", (uint) shell, curr_offset, s->len, eip, eip - (maddr_h) shell, s->syscall);
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


void normalizeShellcode (struct shellcode* s, uint f) {
   #ifndef SYMB 
   printf ("!! Error: you must be in symbolic mode to normalize shellcode\n");
   exit (1);
   #else
   // try to ascertain: 
   //    1) eip; and, 
   //    2) syscall.
   // to find these, decode raw shellcode into equivalent of what dasosf.mod would capture; ie simulate execution until first system call is seen and then use that snapshot to build the output dump
   // eip is needed to help s2e find the true shellcode
   // syscall is nice as it helps eliminate false positives
   char buf[1024];
   snprintf (buf, sizeof (buf), "<< Within normalizeShellcode with params, f: %u\n", f);
   s2e_message (buf);

   // double check that offset is within length
   if (f > s->len) {
      snprintf (buf, sizeof (buf), "!! Error: invalid offset %u", f);
      s2e_kill_state (1, buf);
      printf ("%s\n", buf);
      exit (1);
   }
   printMemRange (s->shell, s->len);
   
   maddr_d lower_bounds = (maddr_d) &(s->shell[0]);
   snprintf (buf, sizeof (buf), "<< About to call dasospreproc_init with shell: 0x%08x (offset of %u not yet applied), shell_len: %u\n", lower_bounds, f, s->len);
   s2e_message (buf);
   
   s2e_dasospreproc_init (lower_bounds, s->len, EIP_UNKNOWN, SYSC_UNKNOWN);
   
   void (*shell) () = (void *) &(s->shell[f]); 
   printf ("<< Calling shell: 0x%08x (adjusted by offset of %u)\n", (uint) shell, f);
   shell ();
   
   s2e_kill_state (1, "!! Error: Shouldn't be here");
   exit (1);
   //s2e_dasospreproc_fini ();
   //s2e_kill_state (0, "<< Ending normalization");
   #endif
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
           "         -Normalizes/preprocesses obfuscated shellcode to similate a dump\n"
           "         -Executes it at any offset\n"
           "         -Outputs it to file (converting raw->dump or dump->raw).\n"
           "      -It also has built-in signal catchers to ensure that it kills itself on bad instructions\n"
           "\n"
           "   In symbolic mode (via S2E) this program executes the input at various offsets in coordination with the DasosPreproc module in order to find the logical start of byte code within the byte array that leads to a system call. If additional information is known, then system calls are filtered by EIP and EAX (sysc number). To do this an offset is given (f) and a number of cases (c) is specified. The wrapper uses state[0] to iteratively fork a state for every case (i = f .. f+c). Each state calls the byte array at its offset i. Before the byte array is called, DasosPreproc is told the memory range to monitor (the byte array) and optionally the EIP and system call number to look for. Once called, processing resides within the DasosPreproc module, further documentation can be found within its code, however all paths should result in the module killing the state (success or failure). If at any time processing returns to the wrapper due to illegal instructions or otherwise, then that state is killed. Once the forked state is killed, state[0] iterates to the next i and forks for it.\n"
           "\n"
           "   Arguments:\n"
           "      --help               This output\n"
           "      -i <filename>        Input file to load into memory. Can be either raw shellcode or a dasosfdump struct\n"
           "                              Exclude this to use built-in helloworld scode\n"
           "                              Type is determined by looking for a special header that exists in dumps\n"
           "      -x                   eXecute byte array\n"
           "      -n                   Normalizes/preprocesses byte array to make a dump struct\n"
           "                              Only works on rawshellcode, then runs it until 1st system call to simulate a DasosFDump capture\n"
           "      -m                   Multiple systemcalls; models past 1st system call\n"
           "                              Other stop exec conditions (like max insns, OOB, etc) used as stop\n"
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
void setSignalHandlers () {
   unsigned int i;
   for (i = 0; i < 32; i++) {
      //signals[i].value = i;
      signals[i].comment[0] = '\0';
   }
   
   // values are architecture dependent, these are x86
   strncpy (signals[0].comment, "Unknown signal", 256);
   strncpy (signals[1].comment, "SIGHUP Hangup detected on controlling terminal", 256);
   strncpy (signals[2].comment, "SIGINT Term Interrupt from keyboard", 256);
   strncpy (signals[3].comment, "SIGQUIT Core Quit from keyboard", 256);
   strncpy (signals[4].comment, "SIGILL Core Illegal Instruction", 256);
   strncpy (signals[5].comment, "SIGTRAP Core Trace/breakpoint trap", 256);
   strncpy (signals[6].comment, "SIGABRT Core Abort signal from abort(3)", 256);
   strncpy (signals[7].comment, "SIGBUS Core Bus error (bad memory access)", 256);
   strncpy (signals[8].comment, "SIGFPE Core Floating point exception", 256);
   strncpy (signals[9].comment, "SIGKILL Term Kill signal", 256);
   strncpy (signals[10].comment, "SIGUSR1 Term User-defined signal 1", 256);
   strncpy (signals[11].comment, "SIGSEGV Core Invalid memory reference", 256);
   strncpy (signals[12].comment, "SIGUSR2 Term User-defined signal 2", 256);
   strncpy (signals[13].comment, "SIGPIPE Term Broken pipe: write to pipe with no readers", 256);
   strncpy (signals[14].comment, "SIGALRM Term Timer signal from alarm(2)", 256);
   strncpy (signals[15].comment, "SIGTERM Term Termination signal", 256);
   strncpy (signals[16].comment, "SIGSTKFLT Term Stack fault on coprocessor (unused)", 256);
   strncpy (signals[17].comment, "SIGCHLD Ign Child stopped or terminated", 256);
   strncpy (signals[18].comment, "SIGCONT Cont Continue if stopped", 256);
   strncpy (signals[19].comment, "SIGSTOP Stop Stop process", 256);
   strncpy (signals[20].comment, "SIGTSTP Stop Stop typed at tty", 256);
   strncpy (signals[21].comment, "SIGTTIN Stop tty input for background process", 256);
   strncpy (signals[22].comment, "SIGTTOU Stop tty output for background process", 256);
   strncpy (signals[23].comment, "SIGURG Ign Urgent condition on socket (4.2BSD)", 256);
   strncpy (signals[24].comment, "SIGXCPU Core CPU time limit exceeded (4.2BSD)", 256);
   strncpy (signals[25].comment, "SIGXFSZ Core File size limit exceeded (4.2BSD)", 256);
   strncpy (signals[26].comment, "SIGVTALRM Term Virtual alarm clock (4.2BSD)", 256);
   strncpy (signals[27].comment, "SIGPROF Term Profiling timer expired", 256);
   strncpy (signals[28].comment, "SIGWINCH Ign Window resize signal (4.3BSD, Sun)", 256);
   strncpy (signals[29].comment, "SIGIO Term I/O now possible (4.2BSD) or SIGPOLL Term Pollable event (Sys V)", 256);
   strncpy (signals[30].comment, "SIGPWR Term Power failure (System V)", 256);
   strncpy (signals[31].comment, "SIGSYS Core Bad argument to routine (SVr4)", 256);

   // other arch values, (not all the above have all their options listed below)
   // see this website: http://www.kernel.org/doc/man-pages/online/pages/man7/signal.7.html
   //strncpy (signals[16].comment, "SIGUSR1 Term User-defined signal 1", 256);
   //strncpy (signals[17].comment, "SIGUSR2 Term User-defined signal 2", 256);
   //strncpy (signals[30].comment, "SIGUSR1 Term User-defined signal 1", 256);
   //strncpy (signals[31].comment, "SIGUSR2 Term User-defined signal 2", 256);
   //strncpy (signals[18].comment, "SIGCHLD Ign Child stopped or terminated", 256);
   //strncpy (signals[20].comment, "SIGCHLD Ign Child stopped or terminated", 256);
   //strncpy (signals[19].comment, "SIGCONT Cont Continue if stopped", 256);
   //strncpy (signals[25].comment, "SIGCONT Cont Continue if stopped", 256);
   //strncpy (signals[17].comment, "SIGSTOP Stop Stop process", 256);
   //strncpy (signals[23].comment, "SIGSTOP Stop Stop process", 256);
   //strncpy (signals[18].comment, "SIGTSTP Stop Stop typed at tty", 256);
   //strncpy (signals[24].comment, "SIGTSTP Stop Stop typed at tty", 256);
   //strncpy (signals[26].comment, "SIGTTIN Stop tty input for background process", 256);
   //strncpy (signals[27].comment, "SIGTTOU Stop tty output for background process", 256);
   //strncpy (signals[10].comment, "SIGBUS Core Bus error (bad memory access)", 256);
   //strncpy (signals[29].comment, "SIGPROF Term Profiling timer expired", 256);
   //strncpy (signals[12].comment, "SIGSYS Core Bad argument to routine (SVr4)", 256);
   //strncpy (signals[16].comment, "SIGURG Ign Urgent condition on socket (4.2BSD)", 256);
   //strncpy (signals[21].comment, "SIGURG Ign Urgent condition on socket (4.2BSD)", 256);
   //strncpy (signals[28].comment, "SIGVTALRM Term Virtual alarm clock (4.2BSD)", 256);
   //strncpy (signals[30].comment, "SIGXCPU Core CPU time limit exceeded (4.2BSD)", 256);
   //strncpy (signals[31].comment, "SIGXFSZ Core File size limit exceeded (4.2BSD)", 256);
   //strncpy (signals[].comment, "", 256);
   //strncpy (signals[].comment, "", 256);
   
   // The signals SIGKILL and SIGSTOP cannot be caught, blocked, or ignored.
   for (i = 1; i < 32; i++) {
      if (signals[i].comment[0] != '\0') {
         signal (i, signal_handler);
      }
   }
   
   return;
} // end fn setSignalHandlers
   
static void signal_handler (int sig) {
   /*switch (sig) {
    case SIGSEGV:
    case SIGILL:*/
   char buf[256];
   snprintf (buf, sizeof (buf), "!! Caught fatal signal: %d: %s", sig, (sig >= 32) ? signals[0].comment : signals[sig].comment);
   printf ("%s\n", buf);
   // if there is any info you want to print out, here is the place...
   s2e_dasospreproc_fini ();
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
   o->normalize = false;
   o->exec_shellcode = false;
   o->multi_syscalls = false;
   
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
         case 'm' :
            o->multi_syscalls = true;
            break;
         case 'n' :
            o->normalize = true;
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
         printf ("!! Warning: disasm range is out of shellcode range, setting to maximum: %u\n", o->shellcode.len - o->disasm_start);
         o->disasm_len = o->shellcode.len - o->disasm_start;
      }
   }
   
   if (o->eip_given_incl && o->shellcode.eip == EIP_UNKNOWN) {
      printf ("!! Warning: given eip is same as eip_unknown value, program will assume no eip given\n");
   }
   
   if (!o->disasm && !o->print && !o->file_out && !o->exec_shellcode && !o->normalize) {
      if (o->source_type == HW) {
         printf ("!! Warning: no mode given and no input specified, what's the point?\n");
      }
   }

   return;
} // end fn verifyOpts

#endif
// end shellcode-wrapper.c
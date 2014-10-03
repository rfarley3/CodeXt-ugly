
/*--------------------------------------------------------------------*/
/*--- Dasosgrind: The Malware Forensics Valgrind tool.   da_main.c ---*/
/*--------------------------------------------------------------------*/

/*
   Copyright (C) 2012 Ryan Farley
      ryanfarley@ieee.org

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.

   You need to follow the tutorial on building a Valgrind tool: valgrind.org/docs/manual/manual-writing-tools.html
   -Instead of autogen.sh run: autoreconf --install
   -Use this config cmd: ./configure --prefix=`pwd`/inst
   -Test a new tool stub by running: inst/bin/valgrind --tool=<tool name> date
   -This tool (dasos) has a tester program, test by running: inst/bin/valgrind --tool=dasos ./dasos/shellcode-wrapper
   
   For development testing:
   -Stay in valgrind-3.7.0/dasos directory
   -Run: make && make install
   -Optionally: ./test.sh
   -Then: ../inst/bin/valgrind --tool=dasos ./shellcode-wrapper -f <shell code file> -o <offset: byte offset within shell at which to begin execution>
   -See shellcode-wrapper.c for its documentation
*/

/* The pub_tool_*.h files are the only .h files a tool should need to #include 
 * Do not include libc, instead use pub_tool_libc*.h
 */
//#include <libdis.h>
//#include "libVGDasosfDump.h"
#include "pub_tool_basics.h"     // basic types and defs that are widely used
#include "pub_tool_tooliface.h"
#include "pub_tool_options.h" // command line option reading functions
#include "pub_tool_libcbase.h"

static Bool da_process_cmd_line_option (Char* arg);
static void da_print_usage (void);
static void da_print_debug_usage (void);

// The following addresses can be found by running ./shellcode-wrapper
// and looking for the address shown on the line:
// Calling shell: 0x0804a040
//Addr64 shell_start1 = 0x0804a040; // helloworld (no shell file specified)
//Addr64 shell_start2 = 0x0804a0a0; // shell loaded from file
Addr64 shell_base = 0x0804a040;   // which is to be used for this instance of this tool
Bool in_shell = False;        // are we in the shell or not?

Addr64 eip = 0x0804a050;          // this is the addr which the shellcode must reach to be a success
                                  // an insn must have a (final byte + 1 == eip) for this exec to be a "success"
Bool success = False;

Addr64 shell_asinmem[1024];       // in order as appears in memory
unsigned int shell_maxIdx = 0;    // furthest away shell byte executed, relative to start
Addr64 shell_asexeced[1024];      // in order as executed
unsigned int shell_len = 0;       // number of bytes of shell executed
unsigned int shell_track[1024];   // each element is the offset from shell_base of the shell_asexeced instruction of the same index
unsigned int shell_exec_cnt[1024];// count the times an offset from shell_base has been executed (to catch loops)

void printfASM (Addr64 addr, Int len);
void printfHumanReadable (unsigned char* addr, unsigned int len);

Bool checkIfShellStart (Addr64 addr);
void storeIntoShell (Addr64 addr, Int len);
Bool insnAligns (Addr64 addr, Int len);
Bool isAddrSyscall (Addr64 addr);


void decodeByteStream (char* hex_str) {
   char decode_cmd[256];
   VG_(sprintf) (decode_cmd, "./dasosUdcli \"%s\"", hex_str);
   //VG_(printf) ("%s", decode_cmd); 
   VG_(system) (decode_cmd);
   return;
} // end fn decodeByteStream


// Given an addr in memory of an insn and the length in bytes that it is, print it in human readable form (mnemonics).
void printfHumanReadable (unsigned char* addr, unsigned int len) {
   // return printfHumanReadable_libdisasm (unsigned char* addr, unsigned int len);
   // try this with libudis86 or objdump
   char decode_cmd[256];
   char byte_str[4];
   unsigned int i;

   decode_cmd[0] = '\0';
   byte_str[0] = '\0';
   VG_(strcpy) (decode_cmd, "./dasosUdcli \"");
   for (i = 0; i < len; i++) {
       VG_(sprintf) (byte_str, "%02x ", ((char *) (addr + i))[0] & 0x000000ff);
       VG_(strcat) (decode_cmd, byte_str);
   }
   VG_(strcat) (decode_cmd, "\"");
   //VG_(printf) ("%s", decode_cmd); 
   VG_(system) (decode_cmd);
   return;
}


// Given a VEX addr, print the raw bytes from memory
void printfASM (Addr64 addr, Int len) {
   unsigned int i;
   char hex_str[256];
   char byte[4];

   VG_(printf) ("  -Insn at addr: 0x%08llx, len: %2d", addr, len);
   // translate addr into an address
   VG_(printf) ("\tHex: ");
   hex_str[0] = '\0';
   // iterate and print len bytes
   for (i = 0; i < len; i++) {
       //VG_(printf) ("0x%02x ", ((char *) (addr + i))[0] & 0x000000ff);
       VG_(sprintf) (byte, "%02x ", ((char *) (addr + i))[0] & 0x000000ff);
       VG_(strcat) (hex_str, byte);
   }
   VG_(printf) ("%s", hex_str);
   for (i = /*MAX_HEX_STR*/7 * 3; i > VG_(strlen) (hex_str); i--) {
      VG_(printf) (" ");
   }
   // convert byte code addr into ASM mnemonic
   // perhaps libdisasm or objdump
   VG_(printf) ("ASM: ");
   decodeByteStream (hex_str);
   //printfHumanReadable ((unsigned char*) addr, (unsigned int) len);
   VG_(printf) ("\n");
   return;
} // end fn printfASM


/* This checks the address given for the IMark insn and compares it
 * to two preset addresses within shellcode-wrapper:
 * 1) the address of char helloworld[0]
 * 2) the address of shellcode[0]
 * See shellcode-wrapper.c for more details. Generally, these are the
 * two options that the wrapper will jump to. Helloworld is a test shell
 * that printf's Hello World. Shellcode is an array that a dump of a 
 * shellcode stored within a file is read into.
 */
Bool checkIfShellStart (Addr64 addr) {
   if (addr == shell_base) {
      in_shell = True;
      return True;
   }
/*shell_start1) {
      shell_base = shell_start1;
      in_shell = True;
   }
   if (addr == shell_start2) {
      shell_base = shell_start2;
      in_shell = True;
   }*/
   return False;
} // end fn checkIfShellStart


/* Sanity check:
 * As insns are executed, store them into 2 arrays:
 * 1) As they appear within memory relative to the start address (note that this may fail if the shel jumps backwards
 * 2) In the order that they are executed
 * This will help verify that all bytes are executed and allows you to compare the control flow
 * Note that data bytes will not be included
 */
void storeIntoShell (Addr64 addr, Int len) {
   unsigned int i;
   unsigned int tmp;
   for (i = 0; i < len; i++) {
      // get the byte as in memory
      tmp = (unsigned int) ((char *) (addr + i) )[0] & 0x000000ff;
      //VG_(printf) ("storing %02x\n", tmp);
      shell_asinmem[addr + i - shell_base] = tmp;
      if ((addr + i - shell_base) > shell_maxIdx) {
         shell_maxIdx = addr + i - shell_base;
      }
      shell_asexeced[shell_len + i] = tmp;  // shell_len + i gets the number of executed bytes by the shell
      shell_track[shell_len + i] = (unsigned int) (addr + i); // addr + i gets the address of the byte
      shell_exec_cnt[addr + i - shell_base]++; // addr + i - shell_base gets the 0 .. 1023 index of the byte within the dump
   }
   shell_len += len;
   return;
} // end fn storeIntoShell


/* Given an addr & len, see if this is the insn that we caught with the kernel mods
 * Note that not only should the alignment match, but the insn type should be int 80 or sys enter
 */
Bool insnAligns (Addr64 addr, Int len) {
   unsigned int byte1, byte2;
   if (len == 2 && (addr + len) == eip) {
      byte1 = (unsigned int) ((char *) addr)[0] & 0x000000ff;
      byte2 = (unsigned int) ((char *) (addr + 1) )[0] & 0x000000ff;
      //VG_(printf) ("  --addr + len: 0x%08llx; eip: 0x%08llx; 0x%02x%02x\n", (addr + len), eip, byte1, byte2);
      if ((byte1 == 0xcd && byte2 == 0x80) ||    // int 80 / interrupt / syscall
          (byte1 == 0x0f && byte2 == 0x34) ) {   // sysenter
         return True;
      }
   }
   return False;
} // end fn insnAligns


Bool isInBounds (Addr64 addr, Int len) {
   //return True;
   Addr64 start = addr;
   Addr64 end = addr + len;
   Addr64 lowBound = eip - 512;
   Addr64 highBound = eip + 512;
   //VG_(printf) ("  --isInBounds? eip: 0x%08llx; addr: 0x%08llx; low: 0x%08llx; start: 0x%08llx; end: 0x%08llx; high: 0x%08llx\n", eip, addr, lowBound, start, end, highBound);
   if (start < lowBound || end > highBound) {
      //VG_(printf) ("  --Out of bounds\n");
      return False;
   }
   return True;
} // end fn isInBound


Bool isAddrSyscall (Addr64 addr) {
   unsigned int byte1, byte2;
   // TODO needs a bounds check to avoid segfaulting
   byte1 = (unsigned int) ((char *) (addr) )[0] & 0x000000ff;
   byte2 = (unsigned int) ((char *) (addr + 1) )[0] & 0x000000ff;
   //VG_(printf) ("  --addr + len: 0x%08llx; 0x%02x%02x\n", (addr + len), byte1, byte2);
   if ((byte1 == 0xcd && byte2 == 0x80) ||    // int 80 / interrupt / syscall
       (byte1 == 0x0f && byte2 == 0x34) ) {   // sysenter
      return True;
   }
   return False;
} // end fn isSyscallNext


Bool wasExeced (unsigned int curr_addr) {
   unsigned int i;
   for (i = 0; i < shell_len; i++) {
      if (curr_addr == shell_track[i]) {
         return True;
      }
   }
   return False;
} // end fn wasExeced


// aka wasExecedTwice
Bool noOverlap () {
   // for each exec'ed byte, ensure that no other insn exec'ed it
   unsigned int i, j;
   for (i = 0; i < shell_len; i++) {
      // if (wasExeced (shell_track[i]) ) won't work, bc instead we are trying to find wasExecedTwice
      for (j = 0; j < shell_len; j++) {
         if (i != j && shell_track[i] == shell_track[j]) {
            return False;
         }
      }
   }
   return True;
} // end fn noOverlap


void showMemMap () {
   unsigned int curr_addr, end_addr, i, j, dump_idx, prev_dump_idx;
   unsigned int min_addr = 0xffffffff;
   unsigned int max_addr = 0x00000000;

   for (i = 0; i < shell_len; i++) {
      if (shell_track[i] < min_addr) {
         min_addr = shell_track[i];
      }
      if (shell_track[i] > max_addr) {
         max_addr = shell_track[i];
      }
   }
   
   // align for print out
   curr_addr = min_addr & 0xfffffff0;
   end_addr = max_addr;
   VG_(printf) ("Dump start_addr: 0x%08x, length: %uB, range: %uB, end_addr: 0x%08x\n", min_addr, shell_len, end_addr - min_addr + 1, end_addr);
   // for loop printing out dump in words with address grid like in gdb
   VG_(printf) ("           0 1 2 3  4 5 6 7  8 9 a b  c d e f   ASCII\n");
   dump_idx = 0;
   prev_dump_idx = dump_idx;
   // for each row
   while (curr_addr < end_addr) {
      VG_(printf) ("0x%08x", curr_addr);
      
      // for each of the 4 words in the row
      for (i = 0; i < 4; i++) {
         VG_(printf) (" ");
         // for each of the 4 bytes in the word
         for (j = 0; j < 4; j++) {
            if (curr_addr < min_addr) {
               VG_(printf) ("  ");
            }
            else if (curr_addr <= end_addr && wasExeced (curr_addr) ) {
               VG_(printf) ("%02x", (unsigned int) ((char *) curr_addr)[0] & 0x000000ff);
            }
            else {
               VG_(printf) ("  ");
            }
            curr_addr++;
         } // end for each byte
      } // end for each word
      
      // now print the ASCII string for the row
      /*VG_(printf) (" ");
      for (i = prev_dump_idx; i < dump_idx; i++) {
         if (isprint (dump.dump[i]) ) {
            VG_(printf) ("%c", dump.dump[i] );
         }
         else {
            VG_(printf) ("-");
         }
      }
      prev_dump_idx = dump_idx;*/
      VG_(printf) ("\n");
   } // end while each row
   VG_(printf) ("\n");
   
   return;
} // end fn showMemMap





/*****************************************************************
 * Standard call back functions, as required by Valgrind core,
 * are below this comment.
 */


/* Allows you to instrument the VEX IR 
 * see VEX/pub/libvex_ir.h, lackey/lk_main.c, cachegrind/cg_main.c
 * ppIRSB (IRSB*) // pretty prints an IRSB
 * addStmtToIRSB (IRSB*, IRStmt*);
 */
static
IRSB* da_instrument ( VgCallbackClosure* closure,
                      IRSB* bb,
                      VexGuestLayout* layout, 
                      VexGuestExtents* vge,
                      IRType gWordTy, IRType hWordTy )
{
   unsigned int i;

   // for each stmt within basic block
   for (i = 0; i < bb->stmts_used; i++) {
      // find IMarks (allows you to filter instructions to ones with information you find useful)
      if (bb->stmts[i]->tag == Ist_IMark) {
         // At some point, the wrapper will jump to the shellcode
         // We want to ignore everything before it does that
         if (in_shell || checkIfShellStart (bb->stmts[i]->Ist.IMark.addr) ) {
            if (!isInBounds (bb->stmts[i]->Ist.IMark.addr, bb->stmts[i]->Ist.IMark.len) ) {
                  VG_(printf) ("  !!FAILURE!! [[0x%08llx,%u]] Execution went out of bounds\n", bb->stmts[i]->Ist.IMark.addr, bb->stmts[i]->Ist.IMark.addr - shell_base);
                  // stop execution
                  VG_(exit) (0);
            }
	    //ppIRStmt (bb->stmts[i]); // sanity check on custom output
            //VG_(printf) ("IMark at stmt %u; addr: 0x%08llx, len: %d\n", i, bb->stmts[i]->Ist.IMark.addr, bb->stmts[i]->Ist.IMark.len);
            // TODO only printASM IMarks within shellcode
            printfASM (bb->stmts[i]->Ist.IMark.addr, bb->stmts[i]->Ist.IMark.len);
	    storeIntoShell (bb->stmts[i]->Ist.IMark.addr, bb->stmts[i]->Ist.IMark.len);
            // now see if this insn's last byte precedes the EIP, ie this was where we caught it
            if (insnAligns (bb->stmts[i]->Ist.IMark.addr, bb->stmts[i]->Ist.IMark.len) ) {
               if (shell_len > 15 && noOverlap () ) {
                  VG_(printf) ("  !!SUCCESS!! Alignment matches [[");
                  for (i = 0; i < shell_len; i++) {
                     VG_(printf) ("%08x", shell_track[i]); //u", shell_track[i]);
                     if (i < (shell_len - 1) ) {
                        VG_(printf) (".");
                     }
                  }
                  VG_(printf) ("]]\n");
                  success = True;
                  showMemMap ();
               }
               // stop execution
               VG_(exit) (0);
            }
            // if this loop has gone on long enough, then exit
            if (shell_exec_cnt[bb->stmts[i]->Ist.IMark.addr - shell_base] > 100) {
               VG_(printf) ("  !!FAILURE!! [[0x%08llx,%u]] A loop repeated too many times\n", bb->stmts[i]->Ist.IMark.addr, bb->stmts[i]->Ist.IMark.addr - shell_base);
               // stop execution
               VG_(exit) (0);
            }
            // if not the insn before the captured syscall, then peek ahead, see if the next instruction is a system call, if so, then exit
            // note that this doesn't catch shell code which jumps to a syscall
            if (bb->stmts[i]->Ist.IMark.addr != (eip - 2 - bb->stmts[i]->Ist.IMark.len) && isAddrSyscall (bb->stmts[i]->Ist.IMark.addr + bb->stmts[i]->Ist.IMark.len) ) {
               VG_(printf) ("  !!FAILURE!! [[0x%08llx,%u]] [[0x%08llx,%u]] Found a syscall before expected\n", bb->stmts[i]->Ist.IMark.addr, bb->stmts[i]->Ist.IMark.addr - shell_base, bb->stmts[i]->Ist.IMark.addr + bb->stmts[i]->Ist.IMark.len, bb->stmts[i]->Ist.IMark.addr + bb->stmts[i]->Ist.IMark.len - shell_base);
               // stop execution
               VG_(exit) (0);
            }
	 }
      }
   } // end for each stmt
   return bb;
} // end fn da_instrument
// dead code analysis is done after this call


/* Only use post_clo_init if a tool provides command line options (CLO) 
 * and must do some initialization after option processing takes place.
 */
static void da_post_clo_init (void) {
   VG_(printf) ("== Using these options, base: 0x%08llx; eip: 0x%08llx\n", shell_base, eip);
   //x86_init (opt_none, NULL, NULL); 
   VG_(memset) (shell_asinmem, '\0', 1024 * sizeof (Addr64) );
   VG_(memset) (shell_asexeced, '\0', 1024 * sizeof (Addr64) );
   VG_(memset) (shell_exec_cnt, '\0', 1024 * sizeof (unsigned int) );
} // end fn da_post_clo_init


/* Present final results, summary of info collected, eg log files
 */
static void da_fini (Int exitcode) {
   unsigned int i;
   //x86_cleanup();

   // Sanity check
   if (shell_len == 0 ) {
      VG_(printf) ("== No shellcode recorded\n");
   }
   else {
      VG_(printf) ("== Shellcode in order as appears in memory:\n== ");
      for (i = 0; i <= shell_maxIdx; i++) {
         VG_(printf) ("\\x%02x ", shell_asinmem[i]);
      }
      VG_(printf) ("\n");
      VG_(printf) ("== Shellcode in order as executed:\n== ");
      for (i = 0; i < shell_len; i++) {
         VG_(printf) ("\\x%02x ", shell_asexeced[i]);
      }
      VG_(printf) ("\n");
   }

   if (!success) {
      //VG_(printf) ("!!FAILURE!!\n");
      //VG_(printf) ("!!FAILURE!! [[0x%08llx,%u]]\n", bb->stmts[i]->Ist.IMark.addr, bb->stmts[i]->Ist.IMark.addr - shell_base);
      VG_(printf) ("!!FAILURE!! [[0x%08x,%u]]\n", shell_track[shell_len - 1] + 1, (Addr64) shell_track[shell_len - 1] - shell_base + 1);
   }
} // end fn da_fini

/* Hello World:
 * 
Shellcode in order as appears in memory:
\xeb \x13 \x59 \x31 \xc0 \xb0 \x04 \x31 \xdb \x43 \x31 \xd2 \xb2 \x0f \xcd \x80 \xb0 \x01 \x4b \xcd \x80 \xe8 \xe8 \xff \xff \xff 
Shellcode in order as executed:
\xeb \x13 \xe8 \xe8 \xff \xff \xff \x59 \x31 \xc0 \xb0 \x04 \x31 \xdb \x43 \x31 \xd2 \xb2 \x0f \xcd \x80 \xb0 \x01 \x4b \xcd \x80 
 */



static void da_pre_clo_init (void) {
   VG_(details_name)            ("Dasosgrind");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("a Valgrind tool for Malware Forensics");
   VG_(details_copyright_author)(
      "Copyright (C) 2012, by Ryan Farley and Xinyuan Wang.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);

   VG_(details_avg_translation_sizeB) ( 275 );

   VG_(basic_tool_funcs)        (da_post_clo_init,
                                 da_instrument,
                                 da_fini);

   /* No needs, no core events to track */
   // see include/pub_tool_tooliface.h
   // detail settings, like VG_(tool_panic) are set here
   // needs (ie what features of core to use) are set here (eg VG_(needs_tool_errors)
   VG_(needs_command_line_options)(da_process_cmd_line_option,
                                   da_print_usage,
                                   da_print_debug_usage);

   // tracks (ie which events within core should notify this tool) are set here (eg VG_(track_*) by providing a fn ptr 
} // end fn da_pre_clo_init


VG_DETERMINE_INTERFACE_VERSION(da_pre_clo_init)

/*****************************************************************
 * Command line call back functions
 */
/*------------------------------------------------------------*/
/*--- Command line options                                 ---*/
/*------------------------------------------------------------*/

/* Command line options */
//static Bool <name>    = <True|False>;
//static Char* <name> = "<value>";

/* options to specify on command line:
Addr64 shell_base;   // addr of 1st byte of shellcode to execute
Addr64 eip;          // this is the addr which the shellcode must reach to be a success
// name of dump file
// name of wrapper program
*/


static Bool da_process_cmd_line_option (Char* arg) {
   //else if VG_STR_CLO(arg, "--eip", eip_str)
   if (VG_BHEX_CLO (arg, "--base", shell_base, 0, (0xffffffff - 1024) ) ) { } //VG_(printf) ("changing shell_base: 0x%08llx\n", shell_base); }
   else if (VG_BHEX_CLO (arg, "--eip", eip, 0, (0xffffffff - 1024) ) ) {} // shell_base, shell_base + 1024) ) { } //VG_(printf) ("changing eip: 0x%08llx\n", eip); }
   else
      return False;

   return True;
} // end fn da_process_cmd_line_option


static void da_print_usage (void) {  
   VG_(printf) (
"    --base=<hex addr, eg 0x804fd5b0>  addr where shellcode starts [yes]\n"
"    --eip=<hex addr, eg 0x804fd5b0>   addr of EIP, the addr immediately after the first system call [yes]\n"
   );
} // end fn da_print_usage


static void da_print_debug_usage (void) {  
   VG_(printf) (
"    (none)\n"
   );
} // end fn da_print_debug_usage



/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/



/*
char canary[] = "\x90\x1f\x1f\x90";
unsigned int canary_len = 4;
unsigned int canary_seen = 0;

void checkCanary (Addr64 addr);

void checkCanary (Addr64 addr) {
   VG_(printf) ("checkingCanary[%u] (0x%02x): 0x%02x\n", canary_seen, canary[canary_seen], ((char *) addr)[0] & 0x000000ff);
   if ((((char *) (addr) )[0] & 0x000000ff) == canary[canary_seen]) {
     canary_seen++;
   }
   else {
     canary_seen = 0;
   }
   if (canary_seen == canary_len) {
      VG_(printf) ("Canary finished at 0x%08x\n", addr);
   }
   return;
} // end fn checkCanary
*/

/*
static void add_one_IRStmt(void)
{
   n_IRStmts++;
}

static void trace_superblock(Addr addr)
{
   VG_(printf)("SB %08lx\n", addr);
}
*/

#ifndef _libDasosfDump_c
#define _libDasosfDump_c
//
//  libDasosfDump.c
//  
//
//  Created by Ryan Farley on 3/13/12.
//  Copyright (c) 2012 George Mason University. All rights reserved.
//
#include "libDasosfDump.h"


unsigned int isThisADasosfDump (char* buf, uint len) {
   if (len < 6) {
      return 0;
   }
   char preamble[DASOSFDUMP_PREAMBLE_LEN] = DASOSFDUMP_PREAMBLE;
   uint i;
   for (i = 0; i < len; i++) {
      if (buf[i] != preamble[i]) {
         return 0;
      }
   }
   // do other things to filter out non-dumps, like if len < sizeof struct dasos_forens_dump - DUMP_SIZE*sizeof (char)
   // or if num_bytes matches what is in the dump
   return 1;
} // end fn isThisADasosfDump


void initDasosfDump (struct dasos_forens_dump* dump, struct shellcode* shell) {
   initDump (dump);
   initShell (shell);
   makeSyscallTable ();
   return;
} // end fn initDasosfDump


void endDasosfDump () {
   return;
} // end fn endDasosfDump


// http://bluemaster.iu.hio.no/edu/dark/lin-asm/syscalls.html
void makeSyscallTable () {
   sprintf (&(syscall_table[4*33]), "sys_write");
   sprintf (&(syscall_table[11*33]), "sys_execve");
   sprintf (&(syscall_table[63*33]), "sys_dup2");
   sprintf (&(syscall_table[102*33]), "sys_socketcall");
   return;
} // end fn makeSyscallTable


// TODO modify to reflect using maddr_d (uint32_t/unsigned ints)
// also most types are static width, this may be archaic now
void dataStructCheck () {
   printf ("There may be data structure incompatibilities.\n");
   printf ("This is a check, compare output on this machine to output on machine which collected the dump.\n");
   
   printf ("struct dasos_forens_deets: %lu\n", (long unsigned int) sizeof (struct dasos_forens_deets) );
   printf ("2 ints: %lu; 256 chars: %lu; 4 u_ints: %lu; dump_timeval: %lu\n", (long unsigned int) 2 * sizeof (int), (long unsigned int) 256 * sizeof (char), (long unsigned int) 4 * sizeof (unsigned int), (long unsigned int) sizeof (struct dump_timeval) );
   printf ("struct dasos_forens_dump: %lu\n", (long unsigned int) sizeof (struct dasos_forens_dump) );
   printf ("6 chars: %lu; 2 u_ints: %lu; deets: %lu; DUMP_SIZE chars: %lu\n", (long unsigned int) 6 * sizeof (char), (long unsigned int) 2 * sizeof (unsigned int), (long unsigned int) sizeof (struct dasos_forens_deets), (long unsigned int) DUMP_SIZE * sizeof (char) );
   printf ("struct shellcode: %lu\n", (long unsigned int) sizeof (struct shellcode) );
   printf ("2 u_ints: %lu; DUMP_SIZE chars: %lu\n", (long unsigned int) 2 * sizeof (unsigned int), (long unsigned int) DUMP_SIZE * sizeof (char) );
   return;
} // end fn dataStructCheck


void initDump (struct dasos_forens_dump* dump) {
   //memset (dump->preamble, '\0', 6 * sizeof (char) );
   strncpy (dump->preamble, DASOSFDUMP_PREAMBLE, DASOSFDUMP_PREAMBLE_LEN);
   dump->start_addr = 0;
   dump->num_bytes = 0;
   dump->deets.check_no = 0;
   dump->deets.pid = 0;
   memset (dump->deets.proc_name, '\0', 256 * sizeof (char) );
   dump->deets.syscall = SYSC_UNKNOWN;
   dump->deets.secret = 0;
   dump->deets.true_secret = 0;
   dump->deets.eip = EIP_UNKNOWN;
   memset (&(dump->deets.ktv), '\0', sizeof (struct dump_timeval) );
   memset (dump->dump, '\0', DUMP_SIZE * sizeof (byte_t) );
   
   return;
} // end fn initDump


void initShell (struct shellcode* shell) {
   shell->addr = 0;
   shell->eip = EIP_UNKNOWN;
   shell->len = 0;
   shell->syscall = SYSC_UNKNOWN;
   memset (shell->shell, '\0', DUMP_SIZE * sizeof (byte_t) );
   return;
} // end fn initShell


void storeShellcodeIntoDump (struct shellcode* s, struct dasos_forens_dump* d, Fill_type t, bool eip_known) {
   if (t == NONE) {
      printf ("!! Error: attempting to fill, but no type specified\n"); // could prob remove this, verifyOpts catches this case
      exit (1);
   }
   
   // at this point shellcode {addr, eip, syscall, len, shell[]} is filled
   // until normalizeShellcode is completed, then eip may still be unknown (syscall_num may be unknown too, but this is safe to skip)
   
   // d->preamble stays the same
   d->start_addr = s->addr;
   d->num_bytes = DUMP_SIZE;
   //d->deets.check_no doesn't matter
   //d->deets.pid doesn't matter
   strncpy (d->deets.proc_name, "dump-from-rawshell", sizeof (d->deets.proc_name) );
   d->deets.syscall = s->syscall; // this handles unknown syscalls as long as the S2E module knows that 1024 (SYSC_UNKNOWN) means unknown (and it does)
   //d->deets.secret doesn't matter
   //d->deets.true_secret doesn't matter
   //d->deets.ktv doesn't matter
   
   // lay down a base coat of filler
   if (t == RANDOM) {
      uint i;
      for (i = 0; i < d->num_bytes; i++) {
         // from http://eternallyconfuzzled.com/arts/jsw_art_rand.aspx
         d->dump[i] = (byte_t) ((rand () * (1.0 / (RAND_MAX + 1.0) ) ) * 256);
      }
   }
   else { //if (t == NULLS) { and default
      memset (d->dump, '\0', sizeof (byte_t) * d->num_bytes);
   }
   
   // put shellcode at correct place (where eip = offset EIP_GOAL_LOC within d->dump
   // EIP_GOAL_LOC is the goal EIP location
   uint scode_start = EIP_GOAL_LOC - s->eip; // if eip is unknown, then scode starts at EIP_GOAL_LOC
   if (eip_known) {
      d->deets.eip = EIP_GOAL_LOC + d->start_addr; // whatever start_addr is... but keep eip absolute (errrr relative to start_addr)
   }
   else {
      d->deets.eip = EIP_UNKNOWN; 
   }
   memcpy (&(d->dump[scode_start]), s->shell, sizeof (byte_t) * s->len);
   return;
} // end fn storeShellcodeIntoDump


void storeDumpIntoShellcode (struct dasos_forens_dump* d, struct shellcode* s) {
   s->addr = d->start_addr;
   if (d->deets.eip != EIP_UNKNOWN && d->deets.eip < d->start_addr) {
      printf ("!! Error: eip < start_addr\n");
      exit (1);
   }
   s->eip = (d->deets.eip == EIP_UNKNOWN) ? EIP_UNKNOWN : d->deets.eip - d->start_addr;
   s->syscall = d->deets.syscall;
   s->len = d->num_bytes;
   if (d->num_bytes > DUMP_SIZE) {
      printf ("!! Error: dump > DUMP_SIZE\n");
      exit (1);
   }
   if (d->num_bytes > (sizeof (s->shell) / sizeof (byte_t) ) ) {
      printf ("!! Error: shell too small for dump\n");
      exit (1);
   }
   memset (s->shell, '\0', sizeof (s->shell) );
   memcpy (s->shell, d->dump, d->num_bytes * sizeof (byte_t) );
   return;
} // end fn storeDumpIntoShellcode


void readFileToMem (char* filename, struct dasos_forens_dump* dump) {
   FILE* DUMP;
   
   if ((DUMP = fopen (filename, "r") ) == NULL) {
      fprintf (stderr, "DASOSF: Can't open dump file: %s\n", strerror (errno) );
      return;
   }
   
   // read from file
   fread (dump, sizeof (struct dasos_forens_dump), 1, DUMP);
   
   fclose (DUMP);
   
   return;
} // end fn readFileToMem


void readFileToDump (char* filename, struct dasos_forens_dump* dump) {
   readFileToMem (filename, dump);
   return;
} // end fn readFileToDump


void readFileToShell (char* filename, struct shellcode* shell) {
   FILE* SHELL;
   
   if ((SHELL = fopen (filename, "r") ) == NULL) {
      fprintf (stderr, "DASOSF: Can't open raw shell file: %s\n", strerror (errno) );
      return;
   }
   
   // read from file, up to size of shell
   shell->len = fread (shell->shell, 1, sizeof (shell->shell), SHELL);
   // normalize read to units that shell->shell uses
   shell->len = shell->len / sizeof (byte_t);
   fclose (SHELL);
   
   shell->addr = 0;
   shell->eip = 0;
   shell->syscall = SYSC_UNKNOWN;
   return;
} // end readFileToShell


void writeDumpToFile (struct dasos_forens_dump* dump, char* filename) {
   FILE* DUMP;
   char dump_filename[256];
   
   snprintf (dump_filename, 256, "%s.dump", filename);
   if ((DUMP = fopen (dump_filename, "w") ) == NULL) {
      fprintf (stderr, "DASOSF: Can't open file to write: %s\n", strerror (errno) );
      return;
   }
   
   fwrite (dump, sizeof (struct dasos_forens_dump), 1 , DUMP);
   
   fclose (DUMP);
   return;
} // end fn writeDumpToFile


// use libudis86 to give human readable output of ASM
void printDisasmSingle (byte_t* raw, uint len) {
   ud_t ud_obj;
   ud_init (&ud_obj);
   ud_set_mode (&ud_obj, 32);
   ud_set_syntax (&ud_obj, UD_SYN_INTEL);
   
   ud_set_input_buffer(&ud_obj, raw, len);
   uint insn_len = 0;
   if ((insn_len = ud_disassemble (&ud_obj) ) != len) {
      printf ("!! Note: skipping, insn did not disasm fully: %u/%u\n", insn_len, len);
      return;
   }
   printf (" %-24s\n", ud_insn_asm (&ud_obj) );

   return;
} // end fn printDisasm_viaLib aka printDisasmSingle


void printDisasmRange (byte_t* raw, uint len) {
   ud_t ud_obj;
   ud_init (&ud_obj);
   ud_set_mode (&ud_obj, 32);
   ud_set_syntax (&ud_obj, UD_SYN_INTEL);
   
   ud_set_input_buffer(&ud_obj, raw, len);
   uint insn_len = 0;
   while (!ud_obj.inp_end && (insn_len = ud_disassemble(&ud_obj) ) ) {
      char* hex1, *hex2;
      char c;
      hex1 = ud_insn_hex(&ud_obj);
      hex2 = hex1 + 16;
      c = hex1[16];
      hex1[16] = 0;
      printf("%-16s %-24s\n", hex1, ud_insn_asm(&ud_obj));
      //printf(" %-24s\n", ud_insn_asm(&ud_obj));
   }

   return;
} // end fn printDisasmRange


void printDump (struct dasos_forens_dump dump) {
   maddr_d curr_addr, end_addr;
   uint i, j, dump_idx, prev_dump_idx;
   
   // align for print out
   curr_addr = dump.start_addr & 0xfffffff0;
   end_addr = dump.start_addr + dump.num_bytes - 1;
   printf ("Dump start_addr: 0x%08x, +512: 0x%08x, len: %uB, end_addr: 0x%08x\n", dump.start_addr, (dump.start_addr + 512), dump.num_bytes, end_addr);
   // for loop printing out dump in words with address grid like in gdb
   printf ("           0 1 2 3  4 5 6 7  8 9 a b  c d e f   ASCII\n");
   dump_idx = 0;
   prev_dump_idx = dump_idx;
   // for each row
   while (curr_addr < end_addr) {
      printf ("0x%08x", curr_addr);
      
      // for each of the 4 words in the row
      for (i = 0; i < 4; i++) {
         printf (" ");
         // for each of the 4 bytes in the word
         for (j = 0; j < 4; j++) {
            if (curr_addr < dump.start_addr) {
               printf ("  ");
            }
            else if (curr_addr <= end_addr && dump_idx < DUMP_SIZE) {
               printf ("%02x", dump.dump[dump_idx] & 0x000000ff);
               dump_idx++;
            }
            else {
               printf ("  ");
            }
            curr_addr++;
         } // end for each byte
      } // end for each word
      
      // now print the ASCII string for the row
      printf (" ");
      for (i = prev_dump_idx; i < dump_idx; i++) {
         if (isprint (dump.dump[i]) ) {
            printf ("%c", dump.dump[i] );
         }
         else {
            printf (".");
         }
      }
      prev_dump_idx = dump_idx;
      printf ("\n");
   } // end while each row
   printf ("\n");
   
   return;
} // end fn printDump


// note that unsigned int shell is really void* shell, and is treated as a char* shell for this function
void printMemRange (byte_t* shell, uint len) {
   maddr_h curr_addr, end_addr;
   uint i, j;
   
   //printf ("shell: 0x%08x, *shell: 0x%08x, &(shell[0]): 0x%08x\n",  shell, (unsigned int) shell, (unsigned int) &(shell[0]) );
   // align for print out
   curr_addr = (maddr_h) shell & CUT_LAST_4b;
   end_addr = curr_addr + len - 1;
   printf ("Shell start_addr: 0x%08x, +512: 0x%08x, length: %uB, range: %uB, end_addr: 0x%08x\n", (uint) curr_addr, (uint) curr_addr + 512, len, (uint) (end_addr - curr_addr + 1), (uint) end_addr);
   // for loop printing out dump in words with address grid like in gdb
   printf ("           0 1 2 3  4 5 6 7  8 9 a b  c d e f   ASCII\n");
   // for each row
   while (curr_addr < end_addr) {
      printf ("0x%08x", (uint) curr_addr);
      char ascii_out[17];
      memset (ascii_out, ' ', 16);
      ascii_out[16] = '\0';
      // for each of the 4 words in the row
      for (i = 0; i < 4; i++) {
         printf (" ");
         // for each of the 4 bytes in the word
         for (j = 0; j < 4; j++) {
            if (curr_addr < (maddr_h) shell) {
               printf ("  ");
            }
            else if (curr_addr <= end_addr) {
               char tmp = ((char *) curr_addr)[0];
               printf ("%02x", (uint) tmp & 0x000000ff );
               ascii_out[(i * 4) + j] = isprint (tmp) ? tmp : '.';
            }
            else {
               printf ("  ");
            }
            curr_addr++;
         } // end for each byte
      } // end for each word
      printf ("  %s\n", ascii_out);
   } // end while each row
   printf ("\n");
   return;
} // end fn printMemRange


void printShell (struct shellcode shell) {
   printMemRange (shell.shell, shell.len);
   return;
} // end fn printShell


void printShellcode (struct dasos_forens_dump dump, struct shellcode shell) {
   struct dasos_forens_dump dump_tmp;
   memcpy (dump_tmp.preamble, dump.preamble, DASOSFDUMP_PREAMBLE_LEN * sizeof (char) );
   dump_tmp.start_addr = shell.addr;
   //dump_tmp.deets.eip = shell.eip // not necessary
   dump_tmp.num_bytes = shell.len;
   memcpy (&(dump_tmp.deets), &(dump.deets), sizeof (struct dasos_forens_deets) );
   memcpy (dump_tmp.dump, shell.shell, shell.len * sizeof (byte_t) );
   
   printDump (dump_tmp);
   
   return;
} // end fn printShellcode


// writes the raw shellcode to a file
void dumpShellcode (char* dump_filename, struct shellcode shell) {
   FILE* shell_file;
   char shell_filename[256];
   
   snprintf (shell_filename, 256, "%s.rawshell", dump_filename);
   
   //printf ("Writing shellcode to file: %s\n", shell_filename);
   
   if ((shell_file = fopen (shell_filename, "w") ) == NULL) {
      fprintf (stderr, "DASOSF: Can't open shell file: %s\n", strerror (errno) );
      return;
   }
   
   // write to file
   fwrite (shell.shell, sizeof (byte_t), shell.len, shell_file);
   
   fclose (shell_file);
   
   return;
} // end fn dumpShellcode


void writeShellcodeToFile (struct shellcode shell, char* dump_filename) {
   dumpShellcode (dump_filename, shell);
   return;
} // end fn writeShellcodeToFile


/*void findShellcode_0 (struct dasos_forens_dump dump, struct shellcode* shell);
 u nsigned int findShellcode_StartViaNops (struct dasos_forens_dump dump);        *
 unsigned int findShellcode_LenViaLastInt80 (struct dasos_forens_dump dump);
 void findShellcode_1 (struct dasos_forens_dump dump, struct shellcode* shell);*/

/*void findShellcode_0 (struct dasos_forens_dump dump, struct shellcode* shell) {
 s hell->addr = 0xbfff0000; *
 shell->len = 6;
 snprintf (shell->shell, DUMP_SIZE, "aaaaaa");
 return;
 } // end fn findShellcode_0
 
 
 unsigned int findShellcode_StartViaNops (struct dasos_forens_dump dump) {
    unsigned int offset;
    // starting at EIP, go backward until you see NOPs
    for (offset = dump.deets.eip - dump.start_addr; offset >= 0 && dump.dump[offset] != (char) 0x90; offset--);
    offset++;
    return dump.start_addr + offset;
 } // end fn findShellcode_StartViaNops
 
 
 unsigned int findShellcode_LenViaLastInt80 (struct dasos_forens_dump dump) {
    unsigned int offset, offset_eip, offset_last_int80;
    offset_eip = dump.deets.eip - dump.start_addr;
    // starting at EIP, go forward until the you see non-code
    offset_last_int80 = offset_eip;
    for (offset = offset_eip; offset < dump.num_bytes; offset++) {
       //if (!isCode (dump.dump[offset]) then break
       // for now this means find the last cd80
       // also consider including any jumps or other ctrl flow instructions
       if (dump.dump[offset] == (char) 0x80 && offset > 0 && dump.dump[offset - 1] == (char) 0xcd) {
          offset_last_int80 = offset;
       }
    }
    return offset_last_int80 + 1 - offset_eip;
 } // end fn findShellcode_LenViaLastInt80
 
 
 void findShellcode_1 (struct dasos_forens_dump dump, struct shellcode* shell) {
    shell->addr = findShellcode_StartViaNops (dump);
    shell->len = dump.deets.eip - shell->addr; // len from shellcode start to eip
    shell->len += findShellcode_LenViaLastInt80 (dump);
    
    memcpy (shell->shell, &(dump.dump[shell->addr - dump.start_addr]), shell->len * sizeof (char) );
    return;
 } // end fn findShellcode_1*/


#endif
// end libDasosfDump.c

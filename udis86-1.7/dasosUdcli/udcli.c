/* -----------------------------------------------------------------------------
 * udcli.c - front end to udis86.
 *
 * Copyright (c) 2004,2005,2006,2007 Vivek Mohan <vivek@sig9.com>
 * All rights reserved.
 * See (LICENSE)
 * -----------------------------------------------------------------------------
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <udis86.h>
#include <config.h>

#define FMT "ll"

#if defined(__DJGPP__) || defined(_WIN32)
# include <io.h>
# include <fcntl.h>
#endif 

#ifdef __DJGPP__
# include <unistd.h>  /* for isatty() */
# define _setmode setmode
# define _fileno fileno
# define _O_BINARY O_BINARY
#endif

/* help string */
static char help[] = 
{
  "Usage: %s [-option[s]] hex string of bytes to disasm\n"
  "Options:\n"
  "    -intel   : Set the output to INTEL (NASM like) syntax. (default)\n"
  "    -o <pc>  : Set the value of program counter to <pc>. (default = 0)\n"
  "    -s <n>   : Set the number of bytes to skip before disassembly to <n>.\n"
  "    -c <n>   : Set the number of bytes to disassemble to <n>.\n"
  "    -noff    : Do not display the offset of instructions.\n"
  "    -nohex   : Do not display the hexadecimal code of instructions.\n"
  "    -h       : Display this help message.\n"
  "    --version: Show version.\n"
  "\n"
  "Udcli is a front-end to the Udis86 Disassembler Library.\n" 
  "http://udis86.sourceforge.net/\n"
};

uint64_t o_skip = 0;
uint64_t o_count = 0;
unsigned char o_do_count= 0;
unsigned char o_do_off = 0;
unsigned char o_do_hex = 0;
unsigned char o_do_x = 1;
unsigned o_vendor = UD_VENDOR_INTEL;
char* hex_str, hex_str_end;

int inp_str_hook(ud_t* u);
int input_hook_x(ud_t* u);

int main(int argc, char **argv)
{
  char *prog_path = *argv;
  ud_t ud_obj;
  char* tmp;
  unsigned int insn_len;

  /* initialize */
  ud_init(&ud_obj);
  ud_set_mode(&ud_obj, 32);
  ud_set_syntax(&ud_obj, UD_SYN_INTEL);

#ifdef __DJGPP__
  if ( !isatty( fileno( stdin ) ) )
#endif
#if defined(__DJGPP) || defined(_WIN32)
  _setmode(_fileno(stdin), _O_BINARY);
#endif  


  argv++;

  /* loop through the args */
  while(--argc > 0) {
	if (strcmp(*argv,"-off") == 0)
		o_do_off = 1;
	else if (strcmp(*argv,"-hex") == 0)
		o_do_hex = 1;
	else if (strcmp(*argv,"-s") == 0) {
		if (--argc) {
			tmp = *(++argv);
			if (sscanf(tmp, "%"  FMT "d", &o_skip) == 0)
				fprintf(stderr, "Invalid value given for -s.\n");
		} else { 
			fprintf(stderr, "No value given for -s.\n");
			printf(help, prog_path);
			exit(EXIT_FAILURE);
		}
        }
	else if (strcmp(*argv,"-c") == 0) {
		if (--argc) {
			o_do_count= 1;
			tmp = *(++argv);
			if (sscanf(tmp, "%" FMT "d", &o_count) == 0)
				fprintf(stderr, "Invalid value given for -c.\n");
		} else { 
			fprintf(stderr, "No value given for -c.\n");
			printf(help, prog_path);
			exit(EXIT_FAILURE);
		}
	}
	else if (strcmp(*argv,"-o") == 0) {
		if (--argc) {
			uint64_t pc = 0;
			tmp = *(++argv);
			if (sscanf(tmp, "%" FMT "x", &pc) == 0)
				fprintf(stderr, "Invalid value given for -o.\n");
			ud_set_pc(&ud_obj, pc);
		} else { 
			fprintf(stderr, "No value given for -o.\n");
			printf(help, prog_path);
			exit(EXIT_FAILURE);
		}
	} else if ( strcmp( *argv, "--version" ) == 0 ) {
		fprintf(stderr, "%s\n", PACKAGE_STRING );
		exit(0);
	} else if((*argv)[0] == '-') {
		fprintf(stderr, "Invalid option %s.\n", *argv);
		printf(help, prog_path);
		exit(EXIT_FAILURE);
	} else {
		hex_str = *argv;
                //hex_str_end = (char *) ((*argv) + (strlen (*argv) * sizeof (char) ) );
                //ud_obj.inp_buff = *argv;
  //u->inp_hook = inp_buff_hook;
  //ud_obj.inp_buff = *argv;
  //ud_obj.inp_buff_end = *argv + (strlen (*argv) * sizeof (char) );
  //inp_init(ud_obj);
	}
	argv++;
  }

	//ud_set_input_hook(&ud_obj, inp_str_hook);	
	ud_set_input_hook(&ud_obj, input_hook_x);
  //ud_obj.inp_buff = hex_str;
  //ud_obj.inp_buff_end = hex_str + (strlen (hex_str) * sizeof (char) );	

  if (o_skip) {
	o_count += o_skip;
	ud_input_skip(&ud_obj, o_skip);
  }

  /* disassembly loop */
 // while (strlen (hex_str) >= 2) { //) {
//printf ("hex_str (%s) len: %u\n", hex_str, strlen (hex_str) );
//getchar ();
	//if (ud_disassemble(&ud_obj) ) {
  insn_len = 0;
  while (!ud_obj.inp_end && (insn_len = ud_disassemble(&ud_obj) ) ) {
	if (o_do_off)
		printf("%016" FMT "x ", ud_insn_off(&ud_obj));
	if (o_do_hex) {
		char* hex1, *hex2;
		char c;
		hex1 = ud_insn_hex(&ud_obj);
		hex2 = hex1 + 16;
		c = hex1[16];
		hex1[16] = 0;
		printf("%-16s %-24s", hex1, ud_insn_asm(&ud_obj));
		hex1[16] = c;
		if (strlen(hex1) > 16) {
			printf("\n");
			if (o_do_off)
				printf("%15s -", "");
			printf("%-16s", hex2);
		}
	} 
	else printf(" %-24s", ud_insn_asm(&ud_obj));

	//printf("\n");

	hex_str += insn_len * 3 * sizeof (char);
	if (strlen (hex_str) < 2) {
           ud_obj.inp_end = 1;
	}
        insn_len = 0;

	//}

//   if (strlen (hex_str) < 2) {
// 	ud_obj.inp_curr = ud_obj.inp_fill;
//         ud_obj.inp_end = 1;
//   }
  }
  
  exit(EXIT_SUCCESS);
  return 0;
}

int inp_str_hook(ud_t* u)
{
  unsigned int c, i;

  if (o_do_count) {
	if (! o_count)
		return UD_EOI;
	else --o_count;
  }

  // there needs to be at least 2 chars left
  if (hex_str >= (hex_str_end - (2 * sizeof (char) ) ) ) {
     return -1;
  }

  i = sscanf (u->inp_buff, "%x", &c); //hex_str, "%x", &c);

  if (i == EOF)
	return UD_EOI;
  if (i == 0) {
	//fprintf(stderr, "Error: Invalid input, should be in hexadecimal form (8-bit).\n");
        //printf ("Error: Invalid input, should be in hexadecimal form (8-bit).\n");
	return UD_EOI;
  }
  if (c > 0xFF) {
	//fprintf(stderr, "Warning: Casting non-8-bit input (%x), to %x.\n", c, c & 0xFF);
        //printf ("Warning: Casting non-8-bit input (%x), to %x.\n", c, c & 0xFF);
  }

  //hex_str += (2 * sizeof (char) );

  return c;
} // end fn inp_str_hook

int input_hook_x(ud_t* u)
{
  unsigned int c, i;

  if (o_do_count) {
	if (! o_count)
		return UD_EOI;
	else --o_count;
  }

  i = sscanf(hex_str, "%x", &c);
  //i = sscanf(u->inp_buff, "%x", &c);

  if (i == EOF)
	return UD_EOI;
  if (i == 0) {
	//fprintf(stderr, "Error: Invalid input, should be in hexadecimal form (8-bit).\n");
        //printf ("Error: Invalid input, should be in hexadecimal form (8-bit).\n");
	return UD_EOI;
  }
  //if (strlen (u->inp_buff) < 2) {
  /*if (strlen (hex_str) < 2) {
        //u->inp_curr = u->inp_fill;
        u->inp_end = 1;
	return UD_EOI;  // -1 is a failure as well
  }
  else {
	u->inp_buff += (i * sizeof (char) );
  }*/
  if (c > 0xFF) {
	//fprintf(stderr, "Warning: Casting non-8-bit input (%x), to %x.\n", c, c & 0xFF);
        //printf ("Warning: Casting non-8-bit input (%x), to %x.\n", c, c & 0xFF);
  }
/*
  if (strlen (hex_str) < 2) {
        hex_str[0] = '\0';
	//u->inp_curr = u->inp_fill;
        //u->inp_end = 1;
  }
  else {
	hex_str += (i * sizeof (char) );
  }*/
  return (int) (c & 0xFF);
}	


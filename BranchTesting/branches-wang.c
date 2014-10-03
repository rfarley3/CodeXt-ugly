/***************
 * 3 Dec 2013 XW
 * There should be four possible combinations of y,z. [Note 3 reachable code possibilities]
 * We can constrain variable x read from file "datafile" to be [-100, 100]
 *
 * For this experiment: 
 *    compile the program in machine code
 *    construct the buffer such that this code has at least 300 random bytes before and after it
 *
 * Code for demonstrating CodeXT/S2E coverage of multiple execution paths via symbolic execution
 * http://www.enderunix.org/docs/en/sc-en.txt
 * http://stackoverflow.com/questions/14290684/how-to-extract-a-few-functions-out-of-a-compiled-elf-executable-no-disassembly
 * https://github.com/dslab-epfl/s2e/blob/master/docs/Howtos/init_env.rst#how-to-symbolically-execute-linux-binaries
 * Symbolic output can be generated using the s2ecmd utility.
 * $ /path/to/guest/s2ecmd/s2ecmd symbwrite 4 | echo                                                                                                                                                                                                                                                                                                                                                                                                                              * The command above will pass 4 symbolic bytes to echo.
 * The easiest way to have your program read symbolic data from files (other than stdin) currently involves a ramdisk. 
 * You need to redirect the symbolic output of s2ecmd symbwrite to a file residing on the ramdisk, then have your program under test read that file. 
 * On many Linux distributions, the /tmp filesystem resides in RAM, so using a file in /tmp works. 
 * This can be checked using the df command: it should print something similar to tmpfs 123 456 123 1% /tmp.
 */

// you can't use includes for shellforge, it has its own include
// if you try to use them, then gcc will barf over conflicting types/definitions
// NORMAL is a compile define to change this between shellforge and normal elf output
#ifdef NORMAL
//#include <stdio.h> // no abstracted IO allowed
#include <stdlib.h>
#include <fcntl.h>
#else
#include "shellforge/include/sfsyscall.h"
#endif

int main () {
   // to generate the file concretely: echo "1" > /tmp/datafile
   char *fname="/dev/shm/dasosdatafile"; // /tmp/datafile";

   //FILE *fp;
   int fd;
   char x, y, z;
    
   // sys_open = syscall# 5
   if ((fd = open (fname, O_RDONLY, 0) ) == -1) 
   //if ((fp=fopen(fname, "rb"))==NULL)
   {
      #ifdef NORMAL
      printf("*** Can't open file: %s\n", fname);
      #endif
      exit(-1);
   }
    
   // sys_read = syscall# 3
   if ((read (fd, (void *) &x, 1) ) != 1)
   //if ((x=fgetc(fp))==EOF)
   { 
      #ifdef NORMAL
      printf("*** End of file of `%s`\n", fname);
      #endif
      exit(-2);
   }
    
   #ifdef NORMAL
   printf("x=%d\n", x);
   #endif
    
   y=0; z=1;
   if (x >= 10)
        y=2;
   else if (x >= 0)
        y=1;
        
   if (y == 0)
        z=0;
        
   if (y==1 && z==0) /* unreachable code */
   {    //z++;
      z=4; // rjf to make y+z unique
      #ifdef NORMAL
      printf("**** should never reach here!\n");
      #endif
   }
    
   #ifdef NORMAL
   printf("x=%d, y=%d, z=%d, x+y+z=%d, y+z=%d\n", x, y, z, x+y+z, y+z);
   printf("to see exit code of y+z run `echo $?`\n");
   #endif

   // sys_close = syscall# 6
   close (fd);
   // sys_exit = syscall# 1
   exit(y+z); // x < 0 -> 0; 0 <= x < 10 -> 2; x >= 10 -> 3, (impossible condition of y==1 && z==0 gives y==1 && z==4) -> 5
   //xorl %ebx,%ebx
   /* __asm__("
    // set ebx to exit code //xorl %ebx,%ebx
    mov $0x1, %eax
    int $0x80
   ");
   */
   return 0;
}

/*
int main () {
   multipath ();
   return 0;
} // end fn main */


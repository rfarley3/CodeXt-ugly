# S2E Preproc Makefile
# RJF Aug 2012

CC    := gcc -Wall -g -m32


default: shellcode-wrapper

clean:
	rm *.o

libDasosfDump.o: libDasosfDump.h libDasosfDump.c
	$(CC) -c libDasosfDump.c

shellcode-wrapper.o: shellcode-wrapper.c
	$(CC) -c shellcode-wrapper.c

shellcode-wrapper: shellcode-wrapper.o libDasosfDump.o
	$(CC) -o shellcode-wrapper -fno-stack-protector -z execstack shellcode-wrapper.o libDasosfDump.o



#dasosfDumpPrint: libDasosfDump.o libDasosBastard.o dasosfDumpPrint.c
#$(CC) -o dasosfDumpPrint -ldisasm dasosfDumpPrint.c libDasosfDump.o libDasosBastard.o
# Make the dasosfdump library and drivers


CC=gcc -Wall -g
CC32=${CC} -m32

default: libDasosfDump-32.o

libDasosfDump-32.o: libDasosfDump.h libDasosfDump.c
	${CC32} -o $@ -c libDasosfDump.c -D IN_32b 

libDasosfDump-64.o: libDasosfDump.h libDasosfDump.c
	${CC} -o $@ -c libDasosfDump.c

#-ludis86
#libDasosfDump.o: libDasosfDump-64.o
#	ln -s libDasosfDump-64.o libDasosfDump.o

#dasosfDumpPrint.o: dasosfDumpPrint.c
#	${CC} -o $@ -c dasosfDumpPrint.c

#dasosfDumpPrint: dasosfDumpPrint.o libDasosfDump-64.o 
#	${CC} -o $@ dasosfDumpPrint.o libDasosfDump-64.o 
#-ldisasm
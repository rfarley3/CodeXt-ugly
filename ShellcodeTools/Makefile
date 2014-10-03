default: dasosf collisions

collisions: testCollisions.c libdasosf
	gcc -Wall -g -o testCollisions -ldisasm testCollisions.c libDasosfDump.o

dasosf: dasosfDumpPrint.c libdasosf
	gcc -Wall -g -o dasosfDumpPrint -ldisasm dasosfDumpPrint.c libDasosfDump.o

libdasosf: libDasosfDump.h libDasosfDump.c
	gcc -Wall -g -c -o libDasosfDump.o libDasosfDump.c

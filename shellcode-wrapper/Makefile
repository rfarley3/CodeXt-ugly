# Make the shellcode-wrapper programe


CC=gcc -Wall -g
CC32=${CC} -m32

default: shellcode-wrapper randfilltester-swrapper



mk.libDasosfDump-32:
	make libDasosfDump-32.o -C ../libDasosf

#mk.libDasosfDump-64:
#	make libDasosfDump-64.o -C ../libDasosf


randfilltester-swrapper.o: randfilltester-swrapper.c
	${CC32} -o $@ -c randfilltester-swrapper.c -DSYMB -DSYMB_OFFSET -D IN_32b

randfilltester-swrapper: randfilltester-swrapper.o mk.libDasosfDump-32
	${CC32} -o $@ -fno-stack-protector -z execstack randfilltester-swrapper.o ../libDasosf/libDasosfDump-32.o -ludis86



randfilltester-swrapper-concrete.o: randfilltester-swrapper.c
	${CC32} -o $@ -c randfilltester-swrapper.c -D IN_32b

randfilltester-swrapper-concrete: randfilltester-swrapper-concrete.o mk.libDasosfDump-32
	${CC32} -o $@ -fno-stack-protector -z execstack randfilltester-swrapper-concrete.o ../libDasosf/libDasosfDump-32.o -ludis86

# use this version for S2E execution
shellcode-wrapper.o: shellcode-wrapper.c
	${CC32} -o $@ -c shellcode-wrapper.c -DSYMB -DSYMB_OFFSET -D IN_32b

shellcode-wrapper: shellcode-wrapper.o mk.libDasosfDump-32
	${CC32} -o $@ -fno-stack-protector -z execstack shellcode-wrapper.o ../libDasosf/libDasosfDump-32.o -ludis86


# use this version for non-S2E execution
shellcode-wrapper-concrete.o: shellcode-wrapper.c
	${CC32} -o $@ -c shellcode-wrapper.c -D IN_32b

shellcode-wrapper-concrete: shellcode-wrapper-concrete.o mk.libDasosfDump-32
	${CC32} -o $@ -fno-stack-protector -z execstack shellcode-wrapper-concrete.o ../libDasosf/libDasosfDump-32.o -ludis86



#shellcode-wrapper-concrete-64.o: shellcode-wrapper.c
#	${CC} -o $@ -c shellcode-wrapper.c

#shellcode-wrapper-concete-64: shellcode-wrapper-concrete-64.o mk.libDasosfDump-64
#	${CC} -o $@ -fno-stack-protector -z execstack shellcode-wrapper-concrete-64.o ../libDasosf/libDasosfDump-64.o -ludis86-64b


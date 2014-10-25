# Make the elf-wrapper programe


CC=gcc -Wall -g
CC32=${CC} -m32

default: elf-wrapper

# use this version for S2E execution
elf-wrapper.o: elf-wrapper.c
	${CC32} -o $@ -c elf-wrapper.c -DSYMB

elf-wrapper: elf-wrapper.o
	${CC32} -o $@ -fno-stack-protector -z execstack elf-wrapper.o


# use this version for non-S2E execution
elf-wrapper-concrete.o: elf-wrapper.c
	${CC32} -o $@ -c elf-wrapper.c

elf-wrapper-concrete: elf-wrapper-concrete.o
	${CC32} -o $@ -fno-stack-protector -z execstack elf-wrapper-concrete.o

hw.elf: hw.c
	${CC32} -o $@ -fno-stack-protector -z execstack hw.c

hw-symb.elf: hw.c
	${CC32} -o $@ -fno-stack-protector -z execstack hw.c -DSYMB

msgLog.elf: msgLog.c
	${CC32} -o $@ -fno-stack-protector -z execstack msgLog.c
	cp $@ ../ByteArrays/.

msgLogSSL.elf: msgLogSSL.c
	${CC32} -o $@ -fno-stack-protector -z execstack msgLogSSL.c -lssl -I/opt/metasploit-4.4.0/msf3/external/source/meterpreter/source/openssl/include
	cp $@ ../ByteArrays/.
	cp my.* ../ByteArrays/.

msgLogSSL-static.elf: msgLogSSL.c
	${CC32} -static -o $@ -fno-stack-protector -z execstack msgLogSSL.c -lssl -I/opt/metasploit-4.4.0/msf3/external/source/meterpreter/source/openssl/include
	cp $@ ../ByteArrays/.
	cp my.* ../ByteArrays/.

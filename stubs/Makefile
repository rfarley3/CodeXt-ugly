# Make the shellcode-wrapper programe

CC32=gcc -Wall -g -m32 -O3

default: stubs-curr

#stubs-curr: mk.stub-symb-iteration
stubs-curr: mk.stub-tut-iteration

mk.stub-symb-iteration: stub-symb-iteration.c
	${CC32} -o stubs-curr -fno-stack-protector -z execstack stub-symb-iteration.c 
	touch $@

mk.stub-tut-iteration: stub-tut-iteration.c
	${CC32} -o stubs-curr -fno-stack-protector -z execstack stub-tut-iteration.c
	touch $@


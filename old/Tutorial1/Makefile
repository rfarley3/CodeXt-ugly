CC32=gcc -Wall -g -m32 -O3

default: abc

abc:
	echo "something is wrong with untouched s2e.h for compiling, investigate later"

tutorial1: mk.tutorial1
#tutorial1: mk.tut1-symbretry
#tutorial1: mk.tut1-fuzzer

mk.tutorial1: tutorial1.c
	${CC32}  -o tutorial1 tutorial1.c
	touch $@

mk.tut1-symbretry: tut1-symbretry.c
	${CC32}  -o tutorial1 tut1-symbretry.c
	touch $@

mk.tut1-fuzzer: tut1-fuzzer.c
	${CC32}  -o tutorial1 tut1-fuzzer.c
	touch $@


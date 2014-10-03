#! /bin/sh

	../shellcode-wrapper/shellcode-wrapper-concrete -i branches-charRanges.s.rawshell -p -d 0,500
	echo '0' > /dev/shm/dasosdatafile
	../shellcode-wrapper/shellcode-wrapper-concrete -i branches-charRanges.s.rawshell -x
	echo "Result char(0): $?"
	echo '5' > /dev/shm/dasosdatafile
	../shellcode-wrapper/shellcode-wrapper-concrete -i branches-charRanges.s.rawshell -x
	echo "Result char(5): $?"
	echo '9' > /dev/shm/dasosdatafile
	../shellcode-wrapper/shellcode-wrapper-concrete -i branches-charRanges.s.rawshell -x
	echo "Result char(9): $?"
	echo '1' > /dev/shm/dasosdatafile

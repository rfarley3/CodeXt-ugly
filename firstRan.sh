#! /bin/sh



echo "Executing the S2E CodeXt Forensics Tracer"
#echo "Stub 0: Run the shellcode wrapper with built-in Hello World"
#./shellcode-wrapper
#echo "Stub 1: Run the shellcode wrapper with built-in Hello World and have S2E exit on first system call"
#./shellcode-wrapper


#echo "Stub 2a: Follow the symbolic execution tutorial"
#./tutorial1
#echo "Stub 2b: Make a symbolic iteration program to test symbolic-izing offset"
#./stubs-curr
#echo "Stub 2c: Run the shellcode wrapper with built-in Hello World using a symbolic value for offset, but only the legit offset and have S2E exit on first system call"
#./shellcode-wrapper -c 1
#echo "Stub 2d: Run the shellcode wrapper with built-in Hello World using a symbex to do all offsets and have S2E exit on first system call"
#./shellcode-wrapper


# Using the new shellcode-wrapper that is a general dasos forensics dump interface
#echo "Stub 3x: Run with input, using a symbex to do all offsets and have S2E exit on first system call"
#1
#./shellcode-wrapper -p -x -f 0 -c 3                # test default
#./shellcode-wrapper -p -x                          # test default
#./shellcode-wrapper -i hw.rawshell -e 16 -x        # test inputting a rawshell (with eip)
#./shellcode-wrapper -i hw.rawshell -x              # test inputting a rawshell (without eip/syscall)
#./shellcode-wrapper -i hw.dump -f 496 -c 22 -x     # test inputting a dump (with eip/syscall)
#./shellcode-wrapper -i hw.dump -x                   # test inputting a dump (with eip/syscall)
## a note about hw2.dump: test inputting a dump (without eip/syscall) with NULL fill
## is helloworld shell
## offset 3 is the first subset of 0's NULL sled, by 6 you should see some OOB calls appearing, 122 is a better number for QA testing
#./shellcode-wrapper -i hw2.dump -x -f 0 -c 3       # quick QA test for subset/impossible 1st insn eliminators
#./shellcode-wrapper -i hw2.dump -x -f 496 -c 40    # this range has the shell, use for full QA test test
#./shellcode-wrapper -i hw2.dump -x                 # full test to show it off
#./shellcode-wrapper -i hw-null-neither.dump -x                 # full test to show it off

## a note about hw4.dump: test inputting a dump (with eip/syscall) with rand fill
## is helloworld shell
#./shellcode-wrapper -i hw4.dump -x -f 70 -c 2      # there is a jmp here that causes problems, QA that we can manage it
#./shellcode-wrapper -i hw4.dump -x                 # full test, but might as well skip to hw5.dump if it passes hw4.dump -f 70..
#./shellcode-wrapper -i hw-null-both.dump -x                 # full test to show it off
#./shellcode-wrapper -i hw-null-noeax.dump -x #forwang
#./shellcode-wrapper -i hw-null-noeip.dump -x #forwang

## a note about hw5.dump: the start of the shellcode is 512
#./shellcode-wrapper -i hw5.dump -x -f 522 -c 3   # this offset gives multiple syscall matches
#2
#./shellcode-wrapper -i hw5.dump -x -f 500 -c 40   # quick QA test for below
## look at 746, 936-1014
#./shellcode-wrapper -i hw-rand-both.dump -x       #
#./shellcode-wrapper -i hw-rand-noeip.dump -x      #
#./shellcode-wrapper -i hw-rand-noeax.dump -x      #
#./shellcode-wrapper -i hw-rand-neither.dump -x    # test inputting a dump (without eip/syscall) with rand fill
#./shellcode-wrapper -i hw-live-both.dump -x       # test inputting a dump (with eip/syscall) with live fill
#./shellcode-wrapper -i hw-live-noeip.dump -x      # test inputting a dump (with eip/without syscall) with live fill
#./shellcode-wrapper -i hw-live-noeax.dump -x      # test inputting a dump (without eip/with syscall) with live fill
#./shellcode-wrapper -i hw-live-neither.dump -x    # test inputting a dump (without eip/syscall) with live fill
## a note about ghttpd.dump: test actual dump input, capture from a live attack
## EIP is 512, cd80 is at 510, 1B of 0x90s before start is 462, start is 466, 
## there are three cd80s: 510 (dup), 526 (system), 550.
#./shellcode-wrapper -i ghttpd.dump -x -f 462 -c 9 # test actual dump input from within nop sled to 1B after last syscall
#3
#./shellcode-wrapper -i ghttpd.dump -x -f 462 -c 89 # test actual dump input from within nop sled to 1B after last syscall
#./shellcode-wrapper -i ghttpd.dump -x -f 462 -c 32 # test actual dump input from within nop sled to 1B after last syscall
#./shellcode-wrapper -i ghttpd.dump -x -f 492 -c 2  # test actual dump input from de-obs payload
#./shellcode-wrapper -i ghttpd.dump -x              # test actual dump input

#echo "Stub 4: Run the shellcode wrapper loading an obfuscated shellcode and see if properly observed"
#./shellcode-wrapper -n                          # test normalizing the default
#./shellcode-wrapper -i tester-rep-safe.rawshell -x -f 0 -c 1         # test a rep insn (safe/nonselfoverwriting)
#./shellcode-wrapper -i tester-rep.rawshell -x -f 0 -c 1              # test a rep insn (selfoverwriting)
#./shellcode-wrapper -i tester-sal-handwritten.rawshell -x -f 0 -c 1  # test a sal insn
#./shellcode-wrapper -i tester-salc.rawshell -x -f 0 -c 1             # test a salc insn (without setting carry)
#./shellcode-wrapper -i tester-salc.rawshell -x -f 10 -c 1            # test a salc insn (with setting carry)
#./shellcode-wrapper -i tester-test.rawshell -x -f 0 -c 1             # test a test insn (from nasm)
#./shellcode-wrapper -i tester-test-handwritten.rawshell -x -f 0 -c 1 # test a test insn (handcoded bytes)

#./shellcode-wrapper -i hw-junkcode.rawshell -x -f 0 -c 1    # Execute a helloworld with junkcode inserted
#./shellcode-wrapper -i hw-xor.rawshell -x -f 0 -c 1         # Execute a xor'ed helloworld
#./shellcode-wrapper -i hw-xorofjunk.rawshell -x -f 0 -c 1   # Execute a xor'ed helloworld with junkcode inserted
#./shellcode-wrapper -i hw-xorofxor.rawshell -x -f 0 -c 1    # Execute a xor'ed of an xor'ed helloworld
#./shellcode-wrapper -i hw-xor1-xor2-xo3-junk-rangedwithoverlap.rawshell -x -f 0 -c 1    # Execute xor(key2,5,10,xor(key1,30,10,xor(key1,10,10,junk(s))))

#./shellcode-wrapper -i hw-admm.rawshell -x -f 0 -c 1          # test admmutate version of hw
#./shellcode-wrapper -i hw-clet.rawshell -x -f 0 -c 1          # test clet version of hw
#./shellcode-wrapper -i hw-alpha2.rawshell -x -f 0 -c 1        # test alpha2 version of hw
#./shellcode-wrapper -i hw-alpha3.rawshell -x -f 0 -c 1        # test alpha3 version of hw
#./shellcode-wrapper -i hw-tapion00.rawshell -x -f 0 -c 1      # test tapion version of hw
#./shellcode-wrapper -i hw-tapionR0.rawshell -x -f 0 -c 1      # test tapion version of hw
#./shellcode-wrapper -i hw-tapion01.rawshell -x -f 0 -c 1      # test tapion version of hw
#./shellcode-wrapper -i hw-tapionR1.rawshell -x -f 0 -c 1      # test tapion version of hw
#./shellcode-wrapper -i hw-countdown.rawshell -x -f 0 -c 1     # test msf countdown version of hw
#./shellcode-wrapper -i hw-call4dword.rawshell -x -f 0 -c 1    # test msf call4dword version of hw
#./shellcode-wrapper -i hw-fnstenv_mov.rawshell -x -f 0 -c 1   # test msf fnstenv version of hw
#./shellcode-wrapper -i hw-jmpcall.rawshell -x -f 0 -c 1       # test msf jmp call version of hw
#./shellcode-wrapper -i hw-bloxor.rawshell -x -f 0 -c 1        # test msf bloxor version of hw
#./shellcode-wrapper -i hw-sganai.rawshell -x -f 0 -c 1        # test msf shikata-ga-nai version of hw
#./shellcode-wrapper -i hw-sganai.rawshell -x -f 0 -c 3        # test forking with efficiency changes


#./shellcode-wrapper -i randfill-102400kb:0-cd80.rawshell -x # -f 2170 -c 10000 # test false positives, there is no shellcode in this

#echo "Stub 5: Trace shellcode through multiple system calls" 
#./shellcode-wrapper -i hw-sganai.rawshell -x -f 0 -c 1  -m       # test msf shikata-ga-nai version of hw
#./shellcode-wrapper -i iterativeEncoder.rawshell -x -f 0 -c 1 -m                # iterative encoded reverse tcp shell
#./shellcode-wrapper -i iterativeEncoder-randadditivekey.rawshell -m -x -f 0 -c 1 # itEnc mutating key rev tcp

#echo "Stub 6: Run the shellcode wrapper loading an obfuscated shellcode and normalize it (output it at the state of the first system call)"
#./shellcode-wrapper -n                          # test normalizing the default

#echo "Stub 7: Run the normalized versions of the shellcodes and see what information we can gather"

#echo "Stub 8: Run symbolic tracking tests"
#./shellcode-wrapper -i avalanche-addition.rawshell -x -f 0 -c 1 
#./shellcode-wrapper -i hw-xor.rawshell -x -f 0 -c 1 
#./shellcode-wrapper -i hw-call4dword.rawshell -x -f 0 -c 1
#./shellcode-wrapper -i hw-sganai.rawshell -x -f 0 -c 1
#./shellcode-wrapper -i BasicTaint.rawshell -x -f 0 -c 1 
#./shellcode-wrapper -i BasicTaintCntDown.rawshell -x -f 0 -c 1 
#./shellcode-wrapper -i BoundedTaint.rawshell -x -f 0 -c 1 

#echo "Stub 9: Trace a shellcode with symbolic data use in conditionals (branching)" 
# with concrete data
#echo "1" > /dev/shm/dasosdatafile 
# instead of /tmp/datafile, the guest has a ramdisk (tmpfs) at /dev/shm, so use /dev/shm/dasosdatafile
# with symbolic data
#./s2ecmd symbwrite 1 | echo > /dev/shm/dasosdatafile 
#./shellcode-wrapper -i branches-wang.c.rawshell -x -f 0 -c 1 -m 
#./shellcode-wrapper -i branches-ryan.s.rawshell -x -f 0 -c 1 -m 
#echo "0" > /dev/shm/dasosdatafile 
#echo "5" > /dev/shm/dasosdatafile 
#echo "9" > /dev/shm/dasosdatafile 
#./shellcode-wrapper -i branches-charRanges.s.rawshell -x -f 0 -c 1 -m
# find that branched code using offsets
#./shellcode-wrapper -i branches-charRanges.s.rawshell -x -f 0 -m
# consider a run without -m
# do the same, but surrounded by random bytes

# try running fully formed executables
# default, no specifications, run a bin and then let this call s2ekill
#./hw.elf
# make a loader to pass the pid/args/init plugin
#./hw.elf  # this should show hello world and then exit
#./hw-symb.elf # this gets codext tracking
#./elf-wrapper ./hw-symb.elf
#./elf-wrapper ./hw.elf dry-run
#./elf-wrapper ./hw.elf
#./elf-wrapper ./msgLog.elf dry-run
#./elf-wrapper ./msgLog.elf
./elf-wrapper ./msgLogSSL.elf
echo "Sleeping 5 so you can see the output"
sleep 5

# catch any orphaned states
./s2ekill

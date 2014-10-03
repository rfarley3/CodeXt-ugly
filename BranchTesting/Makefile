all: branches-test branches-32-sc branches-32-rjf branches-32-chars

# -S output ASM and don't compile to machine code
# -fPIC Position Independent Code: generated code is not dependent on being located at a specific address 
# -Winline
# -finline-functions
# -ffreestanding
# -march=i386 make code compatible with a i386 cpu (limit set of insns used); this implies -mtune=i386 tune optimization for i386 cpu
# -m32 use 32b 
notes:
	# this gcc call is to make a non-shellcode version to debug the coding
branches-test: branches-wang.c
	gcc -m32 -march=i386 -O3 -fPIC -Winline -finline-functions -ffreestanding -DNORMAL -o branches-test branches-wang.c

notes2:
	# gcc C to S tests same line used by shellforge, RJF I had to change it, rem'ed -mcpu=i386 (deprecate synonym for -mtune=i386) added -m32
	#gcc -m32 -march=i386 -O3 -S -fPIC -Winline -finline-functions -ffreestanding -o branches-32.o branches-wang.c
	# gcc S to O tests same line used by shellforge, RJF I had to change it, added -m32
	#gcc -m32 -c -o branches-wang.c.o branches-wang.c.s
branches-32-sc: branches-wang.c
	########### Running Shellforge
	./shellforge/shellforge.py -v 2 -kk -tt -R branches-wang.c

notes4:
#./shellforge/shellforge.py -v 2 -kk -tt -R --in asm branches-ryan.s
	#gcc -m32 -c -o branches-ryan.s.o branches-ryan.s
branches-32-rjf: branches-ryan.s
	./shellforge/shellforge.py -v 2 -kk -tt -R --in asm branches-ryan.s

branches-32-chars: branches-charRanges.s
	./shellforge/shellforge.py -v 2 -kk -tt -R --in asm branches-charRanges.s



notes3:
#  -v <verb> : adjust verbosity. Default is 1, amx is 5.
#  -V        : return version number.
#  -a        : input file is ready to use assembly language
#  -A        : output is assemby languange
#  -C        : ouput c instead of raw shellcode.
#**-R        : raw output (no escape sequences)
#  -t        : output the code to a file (.tst.c) and compile it (imply -c).
#**-tt       : same as -t, then try to run it.
#  -k        : keep intermediate files (.s and .o, or .tst and tst.c with -tt).
#**-kk       : even keep .s and .o if in -tt mode.
#  -x        : xor loader to avoid zero bytes
#  -s        : relocate stack, incompatible with -S 
#  -S        : save/restore all registers (need a working stack, incompatible with -s)
# --in       : input format : 'C' or 'asm' or 'code'
# --out      : output format :  'C' or 'asm' or 'raw'
# --loader   : loader : 'none' or 'xor' or 'alpha'

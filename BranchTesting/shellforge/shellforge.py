#! /usr/bin/env python


#############################################################################
##                                                                         ##
## shellforge.py --- C to shellcode conversion programm                    ##
##              see http://www.cartel-securite.net/pbiondi/shellforge.html ##
##              for more informations                                      ##
##                                                                         ##
## Copyright (C) 2003  Philippe Biondi <biondi@cartel-securite.fr>         ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License as published by the   ##
## Free Software Foundation; either version 2, or (at your option) any     ##
## later version.                                                          ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################

# Inspired from stealth@TESO's HellKit

import os,sys,re,getopt


RCSID="$Id: shellforge.py,v 1.15 2003/08/26 20:45:59 biondi Exp biondi $"
MAJORVERSION="0"
VERSION = MAJORVERSION+"."+RCSID.split()[2]


class Input:
    c = 0
    asm = 1
    code = 2

class Output:
    sh = 0
    c = 1
    raw = 2
    asm = 3

class Loader:
    none = 0
    xor = 1
    alpha = 2


STACKRELOC = 0
SAVEREGS = 0
INPUT = Input.c
OUTPUT = Output.sh
LOADER = Loader.none

VERB = 1
TEST = 0
KEEP = 0


a=sys.argv[0]
INCLUDE=a[:a.rfind("/")]

def printinfo(lvl, x):
    if lvl <= VERB:
        os.write(2,x+"\n")

def error(x,err=1,printusage=0):
    printinfo(0,"ERROR: %s" % x)
    if printusage:
        usage()
    sys.exit(err)
        

def usage():
    printinfo(0, """Usage: shellforge [-v <verb>] [-a] [-z] [-s|-S] [-C|-R|-A] [-t[t]] [-k[k]] <src.c>
  -v <verb> : adjust verbosity. Default is 1.
  -V        : return version number.
  -a        : input file is ready to use assembly language
  -A        : output is assemby languange
  -C        : ouput c instead of raw shellcode.
  -R        : raw output (no escape sequences)
  -t        : output the code to a file (.tst.c) and compile it (imply -c).
  -tt       : same as -t, then try to run it.
  -k        : keep intermediate files (.s and .o, or .tst and tst.c with -tt).
  -kk       : even keep .s and .o if in -tt mode.
  -x        : xor loader to avoid zero bytes
  -s        : relocate stack, incompatible with -S 
  -S        : save/restore all registers (need a working stack, incompatible with -s)
 --in       : input format : 'C' or 'asm' or 'code'
 --out      : output format :  'C' or 'asm or 'raw'
 --loader   : loder : 'none' or 'xor' or 'alpha'""")

try:
    opts=getopt.getopt(sys.argv[1:], "v:VaACRthkxsS",["in=","out=","loader="])
    for opt,optarg in opts[0]:
        if opt == "-h":
            usage()
            sys.exit(0)
        if opt == "-V":
            printinfo(0, "ShellForge v%s\nCopyright (C) 2003  Philippe Biondi <biondi@cartel-securite.fr>" % VERSION)
            sys.exit(0)
        elif opt == "-v":
            try:
                VERB = int(optarg)
            except ValueError,msg:
                raise getopt.GetoptError(str(msg),None)
        elif opt == "-a":
            INPUT = Input.asm
        elif opt == "-C":
            OUTPUT = Output.c
        elif opt == "-A":
            OUTPUT = Output.asm
        elif opt == "-R":
            OUTPUT = Output.raw
        elif opt == "-s":
            STACKRELOC = 1
        elif opt == "-S":
            SAVEREGS = 1
        elif opt == "-x":
            LOADER = Loader.xor
        elif opt == "-t":
            TEST += 1
        elif opt == "-k":
            KEEP += 1
        elif opt == "--in":
            INPUT = getattr(Input, optarg.lower())
        elif opt == "--out":
            OUTPUT = getattr(Output, optarg.lower())
        elif opt == "--loader":
            LOADER = getattr(Loader, optarg.lower())
        
    if len(opts[1]) > 1:
        raise getopt.GetoptError("too many paramters after options.",None)
    elif len(opts[1]) == 0:
        raise getopt.GetoptError("source file missing.",None)
    src = opts[1][0]
except getopt.GetoptError,msg:
    error(msg, printusage=1)
except SystemExit:
    sys.exit(0);
except:
    error("parsing arguments", printusage=1);

if SAVEREGS and STACKRELOC:
    error("options -s and -S are incompatible");

printinfo(2,"** Convert [%s] from [%s] to [%s] with loader [%s]" % (src, INPUT, OUTPUT, LOADER))
printinfo(2,"** Options: stackreloc=%i saveregs=%i test=%i keep=%i" % (STACKRELOC,SAVEREGS, TEST, KEEP))


def mkxordecryptloader(shcode):
    key=0
    ld=""
    for i in range(1,256):
        if chr(i) not in shcode:
            key=i
            break
    if key == 0:
        printinfo(0,"Error: no suitable xor key found.")
        printinfo(0,"Try a better shellcode mutation algorithm on this :")
    else:
        shcode = "".join(map(lambda x: chr(ord(x)^key), shcode))
        length = len(shcode)
        if length < 0x100:
            ld = ("\xeb\x0d\x5e\x31\xc9\xb1"+chr(length)+"\x80\x36"+chr(key)+
                  "\x46\xe2\xfa\xeb\x05\xe8\xee\xff\xff\xff")
        else:
            if length & 0xff == 0:
                length += 1
                ld = ("\xeb\x0f\x5e\x31\xc9\x66\xb9"+chr(length&0xff)+chr(length>>8)+
                      "\x80\x36"+chr(xorkey)+"\x46\xe2\xfa\xeb\x05\xe8\xec\xff\xff\xff")
    return ld+shcode

def mkcpl(x):
    x = ord(x)
    set="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    for c in set:
        d = ord(c)^x
        if chr(d) in set:
            return 0,c,chr(d)
        if chr(0xff^d) in set:
            return 1,c,chr(0xff^d)
    raise Exception,"No encoding found for %#02x"%x


def mkalphadecryptloader(shcode):
    s="hAAAAX5AAAAHPPPPPPPPa"
    shcode=list(shcode)
    shcode.reverse()
    shcode = "".join(shcode)
    shcode += "\x90"*((-len(shcode))%4)
    for b in range(len(shcode)/4):
        T,C,D = 0,"",""
        for i in range(4):
            t,c,d = mkcpl(shcode[4*b+i])
            T += t << i
            C = c+C
            D = d+D
        s += "h%sX5%sP" % (C,D)
        if T > 0:
            s += "TY"
            T = (2*T^T)%16
            for i in range(4):
                if T & 1:
                    s += "19"
                T >>= 1
                if T == 0:
                    break
                s += "I"
    return s+"\xff\xe4"



if INPUT == Input.c:
    printinfo(1,"** Compiling %s" % src)
    
    #original: 
    #f=os.popen("gcc -mcpu=i386 -march=i386 -O3 -S -fPIC -Winline -finline-functions  -ffreestanding -I%s -o -  %s" % (INCLUDE,src))
    # adding -m32
    #f=os.popen("gcc -m32 -mcpu=i386 -march=i386 -O3 -S -fPIC -Winline -finline-functions  -ffreestanding -I%s -o -  %s" % (INCLUDE,src))
    # try -m32
    # -I./shellforge/include -L/usr/lib32 -m32
    # gcc -march=i386 -O3 -S -fPIC -Winline -finline-functions  -ffreestanding -o -  branches-wang.c
    #gcc -m32 -march=i386 -O3 -S -fPIC -Winline -finline-functions -ffreestanding  -o branches-wang-32.o  branches-wang.c
    # -finline-functions enables at -O3
    f=os.popen("gcc -m32 -march=i386 -O3 -S -fPIC -Winline -finline-functions  -ffreestanding -I%s -o -  %s" % (INCLUDE,src))
    inp = f.readlines()
    if f.close():
        error("gcc reported error while compiling %s" % src, err=2)
    
    printinfo(1,"** Tuning original assembler code")
    
    # Move .rodata at the end of .text
    #
    # Move absolute address retrieval at the begining
    # Make %esp point at the begining of the shellcode right after that
    # Put frame stack code after that
    preamb = []
    rodata = []
    textpream = []
    mkstkframe = []
    beforeebx = []
    setebx = []
    afterebx = []
    afterleave = []
    end = []
    
    out = ["# Modified by shellforge v%s\n"%VERSION]
    st1 = []
    st2 = []
    st3 = []
    state=0
    for l in inp:
        printinfo(3, "[%i] %s"% (state, l[:-1]))
        if l.find("@PLT") >= 0:
            error("Error at [%s]: Symbol not found" % (l.strip()), err=2)
        if state == 0:
            if l.find(".rodata") >= 0:
                state = 1
                continue
            elif l.find(".text") >= 0:
                state = 2
            else:
                preamb.append(l);
        if state == 1:
            if l.find(".text") >= 0:
                state = 2
            else:
                rodata.append(l)
        if state == 2:
            textpream.append(l)
            if l.find("main:") >= 0:
                state = 3
            continue
                
        if state == 3:
            mkstkframe.append(l)
            if l.find("mov") >=0 and l.find("%esp") >= 0 and l.find("%ebp") >= 0:
                state = 4
            continue

        if state == 4:
            if l.find("sub") >=0 and l.find(",%esp") >=0:
                mkstkframe.append(l)
            else:
                if rodata:
                    state = 5
                else:
                    state = 7
                
        if state == 5:
            if l.find("push") >= 0 and l.find("%ebx") >= 0:
                state = 6
            else:
                beforeebx.append(l)

        if state == 6:
            setebx.append(l)
            if l.find("GLOBAL_OFFSET_TABLE") >= 0:
                state = 7
            continue
        if state == 7:
            if l.find("leave") >= 0:
                state = 8
            else:
                afterebx.append(l)
        if state == 8:
            if (l.find(".Lfe1:") >= 0 or 
                (l.find(".size") >= 0 and l.find("main") >= 0)):
                state = 9
            else:
                afterleave.append(l)
        if state == 9:
            end.append(l)

    if state != 9:
        error("Automaton failed. Complain at <biondi@cartel-securite.fr>.\n"+
              "Join your C file, the full output of shellforge with -v5, and your gcc version")

    out += preamb+textpream
            
    if STACKRELOC:
        out += [ "\tpopl %eax\n",
                 "\tcall .L649\n",
                 ".L649:\n",
                 "\tpopl %ebx\n",
                 "\tpushl %eax\n",
                 "\taddl $[main-.L649],%ebx\n",
                 "\tmovl %ebx, %eax\n",
                 "\txorl %esp, %eax\n",
                 "\tshrl $16, %eax\n",
                 "\ttest %eax, %eax\n",                       
                 "\tjnz .Lnotinstack\n",                       
                 "\tmovl %ebx,%esp\n",
                 ".Lnotinstack:\n" ]+mkstkframe+beforeebx
    else:
        out += mkstkframe
        if SAVEREGS:
            out.append("\tpusha\n")
        out += beforeebx
        if rodata:
            out += ["\tpush %ebx\n",
                     "\tcall .L649\n",
                     ".L649:\n",
                     "\tpopl %ebx\n",
                     "\taddl $[main-.L649],%ebx\n" ]

    out += afterebx
    if SAVEREGS:
        out.append("\tpopa\n")
    out += afterleave+rodata+end


    if OUTPUT == Output.asm:
        os.write(1, reduce(str.__add__, out))
        sys.exit(0);
        
    f=open(src+".s","w")
    f.writelines(out)
    f.close()



if INPUT == Input.c:
    asmsrc = src+".s"
    printinfo(1,"** Assembling modified asm")
elif INPUT == Input.asm:    
    asmsrc = src
    printinfo(1,"** Assembling %s" % src)

    

if INPUT in [Input.c, Input.asm]:
   # orig: status = os.system("gcc -c -o %s.o %s" % (src,asmsrc))
   # RJF added -m32
    status = os.system("gcc -m32 -c -o %s.o %s" % (src,asmsrc))
    if status != 0:
        error("gcc reported error while compiling modified asm", err=2)

    printinfo(1,"** Retrieving machine code")

    f=os.popen("objdump -j .text -s -z  %s.o" % src)
    inp = f.readlines()
    f.close()


    # Extract machine code
    dump=re.compile("^ [0-9a-f]{4}")
    out = []
    for l in inp:
        if dump.match(l):
            out += l[:42].split()[1:]
    out = "".join(out)
    shcode = ""
    for i in range(len(out)/2):
        shcode += chr(int(out[2*i:2*i+2],16))
    
    if not shcode:
        error("No code in .text section of %s.o !?"%src,err=2)

elif INPUT == Input.code:
    f = open(src)
    shcode = f.read()
    f.close()


if LOADER == Loader.xor:
    printinfo(1, "** Computing xor encryption key")
    shcode = mkxordecryptloader(shcode)
elif LOADER == Loader.alpha:
    printinfo(1, "** encoding with alphanumeric characters")
    shcode = mkalphadecryptloader(shcode)
elif LOADER == Loader.none:
    pass
    
printinfo(1,"** Shellcode forged!")

if TEST:
   if OUTPUT == Output.raw: #RJF
      fd2 = os.open("%s.rawshell"% src, os.O_WRONLY|os.O_CREAT|os.O_TRUNC) #RJF
      os.write(fd2, shcode) # RJF
   fd = os.open("%s.tst.c"% src, os.O_WRONLY|os.O_CREAT|os.O_TRUNC)
   OUTPUT = Output.c
else:
    fd = 1

    
if OUTPUT == Output.raw:
    os.write(fd, shcode)
else:
    if OUTPUT == Output.c:
        os.write(fd, 'unsigned char shellcode[] = \n"')
    for i in range(len(shcode)):
        os.write(fd, "\\x%02x" % ord(shcode[i]))
        if OUTPUT == Output.c and i%19 == 18:
            os.write(fd,'"\n"')
    if OUTPUT == Output.c:
      os.write(fd,'";\nint main(void) { ((void (*)())shellcode)(); }')
    os.write(fd,"\n")

if TEST:
    printinfo(1, "** Compiling test program")
    # RJF added -m32, -g, -fno-stack-protector,  -z execstack
    status = os.system("gcc -g -m32 -fno-stack-protector -z execstack -o %s.tst %s.tst.c" % (src,src))
    if status != 0:
        error("gcc reported error while compiling test program",err=3)
    if TEST > 1:
        printinfo(1, "** Running test program")
        abs=""
        if src[0] != "/":
            abs = "./"
        status=os.system(abs+src+".tst")
        printinfo(1, "\n** Test done! Returned status=%i"% (status>>8))
    else:
        printinfo(1, "** Test program (%s.tst) compiled!" % src)

if TEST == 0 or KEEP < TEST:
    if INPUT == Input.c:
        os.unlink(asmsrc)
    if INPUT in [Input.c, Input.asm]:
        os.unlink(src+".o")
if TEST == 2 and not KEEP:
    os.unlink(src+".tst.c")
    os.unlink(src+".tst")


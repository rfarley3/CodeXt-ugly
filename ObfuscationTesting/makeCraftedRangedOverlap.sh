#! /bin/sh

#xor(key2,5,10,xor(key1,30,10,xor(key1,10,10,junk(s))))
# length of junk decoder: 54
# length of ranged xor decoder: 39

# -o junk already done
./rangedxorencode.pl -i hw-junked.rawshell -o tmp0.rawshell -f 10 -l 10 -k 0xff
./rangedxorencode.pl -i tmp0.rawshell -o tmp1.rawshell -f 69 -l 10 -k 0xff
./rangedxorencode.pl -i tmp1.rawshell -o xor1-xor2-xo3-junk-rangedwithoverlap.rawshell -f 83 -l 10 -k 0x33

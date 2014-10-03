#!/usr/bin/perl -w
# ---------
# xorencode.pl
# ---------

use strict;

if (@ARGV < 1) {
   print "Not enough args. Forgot to specify the input file, exiting\n";
   exit;
}

print "Reading in $ARGV[0]\n";
local $/ = undef;
open (FILE, "<$ARGV[0]"); #../ByteArrays/hw.rawshell');
binmode FILE;
my $buf = <FILE>;
close (FILE);

# simple shellcode (print 'hello')
#my $buf =
#"\xeb\x19\x31\xc0\x31\xdb\x31\xd2\x31\xc9\xb0\x04\xb3\x01" .
#"\x59\xb2\x05\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8" .
#"\xe2\xff\xff\xff\x68\x65\x6c\x6c\x6f";

# hw.rawshell
#my $buf =
#"\xeb\x13\x59\x31\xc0\xb0\x04\x31\xdb\x43\x31\xd2\xb2\x0f\xcd\x80" .
#"\xb0\x01\x4b\xcd\x80\xe8\xe8\xff\xff\xff\x48\x65\x6c\x6c\x6f\x2c" . 
#"\x20\x77\x6f\x72\x6c\x64\x21\x0a\x0d";  


#========================== CODE =============================



# BITS 32
# 
# jmp short callit ; jmp to the call by offset
# 
# xor_decode:
# pop esi       ; get address that call stored, so esi = encrypted_area
# mov edi, esi  ; put esi into esi to use for the call later
# mov edx, esi  ; put esi into edx to use for the call later
# ; cld ?
# mov ecx, 0x29 ; put length to decode into ecx (hw.rawshell is 41/0x29)
# mov ebx, 0xff ; put the xor key into ebx, any value
# xor eax, eax  ; zero the reg where the decoded value will be stored
# push eax      ; zero the top of the stack
# 
# loop_decode:
# lodsb         ; load byte value where esi is pointing into eax
# xor eax, ebx  ; eax ^ ebx (decode eax value using ebx as key)
# stosb         ; store eax (result) where edi is pointing
# ; xor [esi + ecx - 1 ], ebx ; what about this oneliner
# loop loop_decode
# 
# call edx     ; jump to the decoded code
# 
# callit:
# call xor_decode ; call pushes next insn address (encrypted area) onto stack
# ; encrypted_area is appended here

#00000000  EB1A              jmp short 0x1c
#00000002  5E                pop esi
#00000003  89F7              mov edi,esi
#00000005  89F2              mov edx,esi
#00000007  B929000000        mov ecx,0x29  ; MY_CNT
#0000000C  BBFF000000        mov ebx,0xff  ; MY_KEY
#00000011  31C0              xor eax,eax
#00000013  50                push eax
#00000014  AC                lodsb
#00000015  31D8              xor eax,ebx
#00000017  AA                stosb
#00000018  E2FA              loop 0x14
#0000001A  FFD2              call edx
#0000001C  E8E1FFFFFF        call dword 0x2

my $mydecoder =
"\xeb\x1a\x5e\x89\xf7\x89\xf2\xb9" . "MY_CNT" . "\x00\x00\x00\xbb" . "MY_KEY" .
"\x00\x00\x00\x31\xc0\x50\xac\x31\xd8\xaa\xe2\xfa\xff\xd2\xe8\xe1\xff\xff\xff"; 

my $buf_length = do{length $buf};

print "// initial Shellcode length: " . $buf_length . "\n\n";

# IF buf_length is a multiple of 256, we will get NULL bytes whitin MY_CNT.
# so, just add a NOP instruction at the end
if($buf_length % 256 eq 0 ){
	print "// length is a multiple of '256'. Add a NOP.";
	$buf .= "\x90";
}

# Update decoder values
my $bytes_to_decode = 0; 
if($buf_length < 256 ){
	# set ECX counter
   $bytes_to_decode = pack('W', int($buf_length));
	$mydecoder =~ s/MY_CNT/$bytes_to_decode/;
}else{
   print "// Shellcode too long, exiting.";
   exit;
}

my $key = 0xff; # the key that the decoder is expecting
my $key_txt = pack('W', int($key));
$mydecoder =~ s/MY_KEY/$key_txt/;

# convert buf string into an array
my @buf_array = unpack 'a' x length $buf, $buf;

# final shellcode
my $final = "";

# start obfuscation
for(my $i=0; $i< $buf_length ; $i++){
	# copy good shellcode byte into final buffer
	$final	.= chr(ord($buf_array[$i]) ^ $key);
}

my $payload_file = "xor-scode-wo-decoder.rawshell";
print "Outputting encoded form of input to $payload_file\n";
open (FILE, ">$payload_file");
print FILE $final;
close (FILE);

# prefix shellcode with the decoder
$final = $mydecoder . $final ;

# print final shellcode in C language
print "// STUB + SHELLCODE\n";
print "unsigned char buf[] = ";
my $hex = unpack('H*', $final);
for (my $i = 0; $i < length $hex; $i+=2) {
	if($i % 15 eq 0){
		if($i eq 0)	{print "\n\"";}
		else		{print "\"\n\"";}
	}
	print "\\x" . substr $hex, $i, 2;
}
print "\";\n\n";

# print shellcode length (optional)
print "unsigned int buf_len = ". do{length $final} . ";\n";

my $out_file = "xor-scode.rawshell";
print "Outputting final shellcode to $out_file\n";
open (FILE, ">$out_file");
print FILE $final;
close (FILE);


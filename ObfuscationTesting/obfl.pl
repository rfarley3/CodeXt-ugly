#!/usr/bin/perl -w
# ----------
# obf1.pl
# ----------

use strict;

# simple shellcode (print 'hello')
my $buf =
"\xeb\x19\x31\xc0\x31\xdb\x31\xd2\x31\xc9\xb0\x04\xb3\x01" .
"\x59\xb2\x05\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8" .
"\xe2\xff\xff\xff\x68\x65\x6c\x6c\x6f";

#========================== CODE =============================

my $buf_length = do{length $buf};

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

# print final shellcode in C language
print "// NEW SHELLCODE\n";
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

#!/usr/bin/perl -w
# ---------
# xordecode.pl
# ---------

use strict;
use vars qw/ %opt /;

use Getopt::Std;
my $opt_string = 'i:o:f:k:b:';
getopts( "$opt_string", \%opt ) or usage();

if (!$opt{i}) {
   print "No filename, exiting\n";
   exit;
}
my $filename = $opt{i};


my $offset = 0;
$offset = $opt{f} if $opt{f};
my $key = 0xff;  # the key that the decoder is expecting
# user must give hex input
$key = hex($opt{k}) if $opt{k};
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
$keybytes = $opt{b} if $opt{b};
my $keystr = sprintf ("%0" . $keybytes*2 . "x", $key);
my $outfilename = $filename;
$outfilename =~ s/\.[^\.]*//;
$outfilename .= "-decoded.rawshell";
$outfilename = $opt{o} if $opt{o};
print "Using -i $filename -o $outfilename --offset $offset --key 0x$keystr (keybytes: $keybytes)\n";
#" . sprintf ("0x%0" . $keybytes*2 . "x", $key) . "

print "Reading in $filename\n";
local $/ = undef;
open (FILE, "<$filename");
binmode FILE;
my $buf = <FILE>;
close (FILE);

my $buf_length = do{length $buf};

print "// initial Shellcode length: " . $buf_length . "\n\n";

# convert buf string into an array
my @buf_array = unpack 'a' x length $buf, $buf;
my @key_array = map { pack('C', hex($_)) } ($keystr =~ /(..)/g);

# final shellcode
my $final = "";

# start obfuscation
for(my $i = $offset; $i < $buf_length ; $i++){
	# copy good shellcode byte into final buffer
   #my $h_key = $key_array[$i%$keybytes];
   my $i_key = ord($key_array[$i%$keybytes]);
   #printf ($i . "_k: 0x%02x v 0x%02x\n", $i_key, $key);
	$final .= chr(ord($buf_array[$i]) ^ $i_key);
}


open (FILE, ">$outfilename");
print FILE $final;
close (FILE);

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


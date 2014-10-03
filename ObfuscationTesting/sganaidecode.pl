#!/usr/bin/perl -w
# ---------
# xordecode.pl
# ---------

use strict;
use vars qw/ %opt /;

use Getopt::Std;
my $opt_string = 'i:o:k:b:';
getopts( "$opt_string", \%opt ) or usage();

if (!$opt{i}) {
   print "No input, exiting\n";
   exit;
}
my $use_file = 0;
my $filename = $opt{i};
my $input = $opt{i};
if ($opt{i} =~ m/\./) {
   $use_file = 1;
}

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
my $use_outfile = 0;
my $outfilename = "notenabled"; #$filename;
#$outfilename =~ s/\.[^\.]*//;
#$outfilename .= "-decoded.rawshell";
if ($opt{o}) {
   $use_outfile = 1;
   $outfilename = $opt{o};
}
print "Using -i $filename -o $outfilename --offset $offset --key 0x$keystr (keybytes: $keybytes)\n";
#" . sprintf ("0x%0" . $keybytes*2 . "x", $key) . "

my $buf = "";
my $buf_length = 0;
my @buf_array = (); 
if ($use_file) {
   print "Reading in $filename\n";
   local $/ = undef;
   open (FILE, "<$filename");
   binmode FILE;
   $buf = <FILE>;
   close (FILE);
   @buf_array = unpack 'a' x length $buf, $buf;
   $buf_length = do{length $buf};
}
else {
   print "Reading in $input\n";
   @buf_array = map { pack('C', hex($_)) } ($input =~ /(..)/g);
   $buf_length = $#buf_array + 1;
   print "Read in $buf_length" . "B " . $input . "\n";
}

print "// initial Shellcode length: " . $buf_length . "\n\n";

# convert buf string into an array
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


if ($use_outfile) {
   open (FILE, ">$outfilename");
   print FILE $final;
   close (FILE);
}

# print final shellcode in C language
print "// result:\n";
my $hex = unpack('H*', $final);
for (my $i = 0; $i < length $hex; $i+=2) {
	if($i % 15 eq 0){
		if($i eq 0)	{print "\n";}
		else		{print "\n";}
	}
	substr $hex, $i, 2;
}
print "\n\n";

# print shellcode length (optional)
print "unsigned int buf_len = ". do{length $final} . ";\n";


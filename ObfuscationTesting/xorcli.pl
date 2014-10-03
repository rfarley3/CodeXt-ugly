#!/usr/bin/perl -w
# ---------
# xorcli.pl
# ---------

use strict;
use vars qw/ %opt /;

use Getopt::Std;
my $opt_string = 'i:o:k:b:f:';
getopts( "$opt_string", \%opt ) or usage();

if (!$opt{i}) {
   print "No input, exiting\n";
   exit;
}
my $use_file = 0;
my $filename = $opt{i};
my $input = hex($opt{i});
if ($opt{i} =~ m/\./) {
   $use_file = 1;
}
my $inputstr = sprintf ("%02x", $input);

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
print "Using -i $filename|0x$inputstr -o $outfilename --offset $offset --key 0x$keystr (keybytes: $keybytes)\n";
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
   print "// initial Shellcode length: " . $buf_length . "\n\n";
}
else {
   #my $input_str = $input;
   print "Reading in $inputstr\n";
   #$input = hex ($input_str);
   #$input_str = sprintf ("%0" . $keybytes*2 . "x", $key);
   #$input = sprintf ("%0" . $keybytes*2 . "x", $key);
   @buf_array = map { pack('C', hex($_)) } ($inputstr =~ /(..)/g);
   $buf_length = $#buf_array + 1;
   print "Read in $buf_length" . "B: ";
   for (my $i = 0; $i < $buf_length; $i++) {
      printf("%02x ", ord($buf_array[$i]));
   }
   print "\n";
}


# convert buf string into an array
my @key_array = map { pack('C', hex($_)) } ($keystr =~ /(..)/g);

# final shellcode
my $final = "";

# start obfuscation
my $length = 0;
for(my $i = $offset; $i < $buf_length ; $i++){
	# copy good shellcode byte into final buffer
   #my $h_key = $key_array[$i%$keybytes];
   my $i_key = ord($key_array[$i%$keybytes]);
   my $i_b   = ord($buf_array[$i]);
   my $i_f   = chr($i_b ^ $i_key);
   printf ("k: 0x%02x ^ b: 0x%02x = 0x%02x\n", $i_key, $i_b, ord($i_f) );
	$final .= chr(ord($i_f));
   $length++;
}
print "\n";


if ($use_outfile) {
   print "Outputting to file: $outfilename\n";
   open (FILE, ">$outfilename");
   print FILE $final;
   close (FILE);
}

# print final shellcode in C language
print "// Result $length" . "B: ";
my $hex = unpack('H*', $final);
print "$hex\n";

exit;

#! /usr/bin/perl -w

use strict;

# script out running tests
my $outputdir = "SavedOutputs/acsac";

my @bytearrays = ();
# add a push of the filename within ByteArrays/ that you want to execute and their execution options
# filenames can not have spaces in them or option parse will fail
push @bytearrays, "hw-null-both.dump -x";
push @bytearrays, "hw-live-both.dump -x";
push @bytearrays, "hw-live-neither.dump -x";
push @bytearrays, "hw-rand-both.dump -x";
push @bytearrays, "hw-rand-neither.dump -x";
push @bytearrays, "hw-rand-noeip.dump -x";
push @bytearrays, "hw-rand-noeax.dump -x";

# consider making byte arrays allow options as well

# for each file to test
foreach my $bytearray (@bytearrays) {
   # create the script that the guest will load, it needs the bytearray filename and options
   $bytearray =~ m/^([^\s]*)\s(.*)$/;
   $bytearray = $1;
   my $options = $2;
   print "making firstRan.sh with: $bytearray and $options\n";
   open (FIRST_RAN, ">firstRan.sh");
   print FIRST_RAN "#! /bin/sh\n./shellcode-wrapper -i $bytearray $options\n";
   close FIRST_RAN;

   # run the system on that byte array
   # consider replacing this with the make run commands (so I can edit and compile while a batch is running)
   `make run`;

   # change the input filename into the name that we want to store the file as
   my $file_out = $bytearray;
   $file_out =~ s/\.[a-z]*$/.txt/;   # change extension to txt

   # some changes specific to these byte array names
   $file_out =~ s/hw-//;       # drop hw- prefix
   $file_out =~ s/live/captured/;  # change naming convention
   $file_out =~ s/noeip/eax/;  # change naming convention
   $file_out =~ s/noeax/eip/;

   # store the file in a safe place
   `cp s2e-last/debug.txt $outputdir/$file_out`;
}


exit;
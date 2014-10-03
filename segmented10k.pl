#! /usr/bin/perl -w

use strict;

my $DRY_RUN = 0;

# script out running tests
my $outputdir = "SavedOutputs/10k";
# test for existence of outputdir

my @bytearrays = ();
# add a push of the filename within ByteArrays/ that you want to execute and their execution options
# filenames can not have spaces in them or option parse will fail
for (my $i = 0; $i < 10; $i++) {
   my $str = "randfill-10240kb:11-cd80.rawshell;-x -f " . ($i*1024) . " -c 1024";
   push @bytearrays, $str;
}

# consider making byte arrays allow options as well

# for each file to test
foreach my $bytearray (@bytearrays) {
   # create the script that the guest will load, it needs the bytearray filename and options
   $bytearray =~ m/^(.*);(.*)$/;
   $bytearray = $1;
   my $options = $2;
   print "making firstRan.sh with: $bytearray and $options\n";
   if (!$DRY_RUN) {
      open (FIRST_RAN, ">firstRan.sh");
      print FIRST_RAN "#! /bin/sh\n./shellcode-wrapper -i $bytearray $options\n";
      close FIRST_RAN;

      # run the system on that byte array
      # consider replacing this with the make run commands (so I can edit and compile while a batch is running)
      `make run`;
   }


   # change the input filename into the name that we want to store the file as
   my $file_out = $bytearray;
   $options =~ s/.*-f\s*(\d+).*-c\s*(\d+)\s*/$1-$2/;
   $file_out =~ s/\.[a-z]*$/-$options.txt/;   # change extension to txt
   print "storing debug.txt into $outputdir/$file_out\n";

   # store the file in a safe place
   if (!$DRY_RUN) {
      `cp s2e-last/debug.txt $outputdir/$file_out`;
   }
} # end foreach bytearray to execute


exit;
#! /usr/bin/perl -w

use strict;

my $DRY_RUN = 0;
# script out running tests
my $outputdir = "SavedOutputs/1krep20";
my $reps = 20;

my @bytearrays = ();
# add a push of the filename within ByteArrays/ that you want to execute and their execution options
# filenames can not have spaces in them or option parse will fail
push @bytearrays, "randfill-1024kb:648.rawshell;-x";

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
   }

   for (my $i = 0; $i < $reps; $i++) {
      # run the system on that byte array
      # consider replacing this with the make run commands (so I can edit and compile while a batch is running)
      if (!$DRY_RUN) {
         `make run`;
      }

      # change the input filename into the name that we want to store the file as
      my $file_out = $bytearray;
      $file_out =~ s/\.[a-z]*$/-rep$i.txt/;   # change extension to txt

      # store the file in a safe place
      print "storing output into $outputdir/$file_out\n";
      if (!$DRY_RUN) {
         `cp s2e-last/debug.txt $outputdir/$file_out`;
      }
   } # end foreach rep
} # end foreach bytearray


exit;

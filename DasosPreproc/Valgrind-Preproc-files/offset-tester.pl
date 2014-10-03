#! /usr/bin/perl -w

# offset-tester.pl runs a shellcode dump at various offsets
# In order to experiment with collision rates

use strict;


print "Running offset collision tester\n";
print "This script assumes that the dump files contain 1024B and that the EIP is at 512.\n";
my $base; # address of the start of the execution. You can find this value by running the wrapper, it's in the output.
my $eip;  # address of the EIP. You must know this about the byte stream, either manually, from a well structured dump (eg all are at 512), or from the dump.deets.eip value inside the dump file (modify the wrapper to output it)
my $dumpfile = "";
my $rawfile = "";
my $offset = 0;
my $tests = 1024;
my $verbose = 0;

if ($#ARGV == -1) { # hello
   $eip = 0x0804a5f0;
   $base = 0x0804a5e0;
}
else {
   for (my $i = 0; $i <= $#ARGV; $i++) {
      if ($ARGV[$i] eq "-d") { # dump file
         $base = 0x0804a770;
         $eip = 0x0804a970;   # assumes that the EIP is at offset 512
         $i++;
         $dumpfile = $ARGV[$i];
      }
      elsif ($ARGV[$i] eq "-f") { # raw shell file
         #$eip = ?;  # raw shell file
         #$base = ?; # raw shell file
         $i++;
         $rawfile = $ARGV[$i];
      }
      elsif ($ARGV[$i] eq "-o") { # offset to start at
         $i++;
         $offset = $ARGV[$i];
      }
      elsif ($ARGV[$i] eq "-c") { # number from offset
         $i++;
         $tests = $ARGV[$i];
      }
      elsif ($ARGV[$i] eq "-v") { # be verbose
         $i++;
         $verbose = 1;
      }
      else {
         print "Error parsing command line arguments\n";
         print "Usage:\n";
         print "   -d <dump file>; the file which contains the dump\n";
         print "   -o <offset>; the number of the byte to begin within the dump\n";
         print "   -c <count>; the number of offsets to iterate through\n";
         exit;
      }
   }
}

my $eip_idx = $eip - $base;
printf ("Using, base: 0x%08x; eip: 0x%08x; eip_idx: $eip_idx\n", $base, $eip);
my @successes = ();
my @sigs = ();
my @outputs = ();

&main;
&summary;
exit;

sub main {
   my $end_i = $offset + $tests - 1;
   if ($end_i > 1023) {
      $end_i = 1023;
   }
   if ($end_i <= 0) {
      $end_i = $offset;
   }
   for (my $i = $offset; $i <= $end_i; $i++) { #($eip_idx - 1); $i++) {
      my $date = `date`;
      print "$date";
      my $command = sprintf ("../inst/bin/valgrind --tool=dasos --base=0x%08x --eip=0x%08x ./shellcode-wrapper ", ($base + $i), $eip);
      if ($dumpfile ne "") {
         $command .= "-d $dumpfile ";
      }
      elsif ($rawfile ne "") {
         $command .= "-f $rawfile ";
      }
      $command .= "-o $i 2>&1";
      print "Running $command\n";
      my @output = `$command`;
      if ($verbose) {
         print "\n\n-----START verbose output-----\n";
         print @output;
         print "\n-----END verbose output-----\n\n\n";
      }
      foreach my $line (@output) {
         if ($line =~ m/SUCCESS/) {
            print "Offset $i was success\n";
            push (@successes, $i);
            push (@sigs, $line);
            push (@outputs, join ('', @output) ); 
         }
      }
   }
   return;
} # end fn main


sub summary {
   printf ("\n%d offsets were a success", $#successes + 1);
   if ($#successes == -1) {
      print "\n";
      return;
   }
   print " (";
   foreach my $success (@successes) {
      print "$success ";
   }
   my @uniques = ();
   my @uniques_output = ();
   my @uniques_sigs = ();
   for (my $i = 0; $i <= $#sigs; $i++) {
      $sigs[$i] =~ s/.*\[\[(.*)\]\]/$1/;
      my $is_unique = 1;
      for (my $j = 0; $j < $i; $j++) {
         if ($sigs[$j] =~ m/^.*$sigs[$i]/) {
            $is_unique = 0;
         }
      }
      if ($is_unique) {
         push (@uniques, $successes[$i]);
         push (@uniques_output, $outputs[$i]);
         push (@uniques_sigs, $sigs[$i]);
      }
   }
   print "), of these " . ($#uniques + 1) . " were not subsets of earlier offsets:\n";
   #printf ("), of these %d were not subsets of earlier offsets:\n", $#uniques + 1);
   for (my $i = 0; $i <= $#uniques; $i++) {
      printf ("%d th (0x%x) offset's output:\n", $uniques[$i], $uniques[$i]);
      print $uniques_output[$i] . "\n";
   }
   print "\n";
   print "That was a lot of output, to summarize, there were " . ($#uniques + 1) . " unique, non-subset offsets (";
   foreach my $unique (@uniques) {
      print "$unique ";
   }
   print ")\n";
   #my $unique_idx = 0;
   my $largest_res_idx = 0; #$unique_idx;
   my $largest_res_size = 0;
   for (my $i = 0; $i <= $#uniques; $i++) {
      #my $res = getEnclosure ($uniques_sigs[$i]);
      my $res = getDensity ($uniques_sigs[$i]);
      print "$uniques[$i] (res: $res; largest prev seen: $largest_res_size)\n";
      if ($res > $largest_res_size) {
         $largest_res_size = $res;
         $largest_res_idx = $i; #unique_idx;
      }
      #$unique_idx++;
   } # end foreach

   print "Of these, " . $uniques[$largest_res_idx] . " has the greatest density:\n";
   print $uniques_output[$largest_res_idx] . "\n";

   return;
} # end fn summary


sub getDensity ($) {
   my $sig = $_[0];
   my $lowest_addr = hex ("0xffffffff");
   my $greatest_addr = 0;
   my @addrs = split (/\./, $sig); #$uniques_sigs[$i]);
   foreach my $addr (@addrs) {
      $addr =~ s/\n//g;
      if (hex ($addr) < $lowest_addr) {
         $lowest_addr = hex ($addr);
      }
      if (hex ($addr) > $greatest_addr) {
         $greatest_addr = hex ($addr);
      }
      #print "addr: $addr";
   }
   #my @ordered = sort {hex ($a) <=> hex ($b)} @addrs; # sort in increasing value, this detects compact code near EIP that jumps
   # otherwise detect the longest contiguous string of code irrespective of jumps that doesn't necessarily end on EIP

   # determine lowest addr
   # determine greatest addr
   # determine num_bytes executed
   #density = num_bytes / (greatest - lowest)
   my $density = $#addrs / ($greatest_addr - $lowest_addr); #($ordered[$#ordered] - $ordered[0]);

   #   my $enclosure_size = 0;
   #   my $j = $#addrs;
   #   my $addr_curr = hex ($addrs[$j]);
   #   my $addr_prev = $eip;
   #   while ($j > 0 && $addr_curr == $addr_prev - 1) {
   #      #printf ("prev: 0x%08x, curr: 0x%08x ($addrs[$j]); ", $addr_prev, $addr_curr);
   #      $enclosure_size++;
   #      $addr_prev = $addr_curr;
   #      $j--;
   #      $addr_curr = hex ($addrs[$j]);
   #   }
   return $density;
} # end fn getDensity


sub getEnclosure ($) {
   my $sig = $_[0];
   #foreach my $unique (@uniques) {
      #print "Doing $uniques[$i]\n";
      # for each unique break the sig into an array of addresses
      #my $line = $unique_sigs[$i]; #uniques[$unique_idx]];
      #$line =~ s/^.*\[\[//;
      #$line =~ s/]].*$//;
      #print "line: $uniques_sigs[$i]"; #$line";
      my @addrs = split (/\./, $sig); #$uniques_sigs[$i]);
      foreach my $addr (@addrs) {
         $addr =~ s/\n//g;
         #print "addr: $addr";
      }
      # sort ($addrs); # sort in increasing value, this detects compact code near EIP that jumps
      # otherwise detect the longest contiguous string of code irrespective of jumps that doesn't necessarily end on EIP

      # determine enclosure size
      my $enclosure_size = 0;
      my $j = $#addrs;
      my $addr_curr = hex ($addrs[$j]);
      my $addr_prev = $eip;
      while ($j > 0 && $addr_curr == $addr_prev - 1) {
         #printf ("prev: 0x%08x, curr: 0x%08x ($addrs[$j]); ", $addr_prev, $addr_curr);
         $enclosure_size++;
         $addr_prev = $addr_curr;
         $j--;
         $addr_curr = hex ($addrs[$j]);
      }
   return $enclosure_size;
} # end fn getEnclosure


# end offset-tester.pl
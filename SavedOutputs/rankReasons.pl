#! /usr/bin/perl -w

#use strict;

my $in = $ARGV[0];
if ($in eq "") {
   exit;
}

print "Ranking Termination Reasons from $in\n";


my %reasons = (
   "Positive", 0,           # EIP reached and syscall accepted as valid
   "Kern Runaway", 0,       # Exec'ed in the kernel too long
   "OOB Jump", 0,           # Jumped out of bounds
   "Other", 0,              # Cummulative across all the other OOBs, generally execution control has been lost and will not return
   "Bad Jump", 0,           # Jumped to a place that was not predicted
   "FP, Subset", 0,         # This positive is a suffix of a previous positive
   "FP, irregular EAX", 0,  # This positive has a system call number > 256 
   "Opcode", 0,             # This was killed cleanly, some condition: 
   "FP, Wrong EAX", 0);     # This positive had the wrong system call number

# 1016 [State 1016] Terminating state 1016 with message 'eliminated a state that exec'ed out of module bounds unexpectedly'

my @msgs = `cat $in | grep "Term" | grep "with message" | sed -e "s/^.* '//" | sed -e "s/'\$//" | sort | uniq --count`;

my $tot = 0;
foreach my $msg (@msgs) {
   $msg =~ m/^\s*(\d+)\s(.*$)/;
   $tot += $1;
   my $txt = $2;
   my $txt2 = $2;
   if ($txt =~ m/EIP reached, success/) {
      #$reasons{"Positive"}++;
      $txt2 =~ s/(^\s*\d+\s).*/\1 Positive/;
      print "$txt2\nsdfasdfasd\n";
   }
   elsif ($txt =~ m/module bounds, in the/) {
      $reasons{"Kern Runaway"} = $reasons{"Kern Runaway"} + 1;
   }
   elsif ($txt =~ m/module bounds unex/) {
      $reasons{"OOB Jump"}++;
   }
   elsif ($txt =~ m/too many killable/) {
      $reasons{"Other"}++;
   }
   elsif ($txt =~ m/at unexpected loc/) {
      $reasons{"Bad Jump"}++;
   }
   elsif ($txt =~ m/false positive, execution path subset/) {
      $reasons{"FP, Subset"}++;
   }
   elsif ($txt =~ m/false positive, out of range syscall/) {
      $reasons{"FP, irregular EAX"}++;
   }
   elsif ($txt =~ m/terminated by opcode/) {
      $reasons{"Opcode"}++;
   }
   elsif ($txt =~ m/wrong syscall found in memory range/) {
      $reasons{"FP, Wrong EAX"}++;
   }
   print $txt;
}

#Ranking Termination Reasons from rand-both.txt
#      1 EIP reached, success
#     23 eliminated a state that exec'ed out of module bounds, in the kernel, for too long
#    772 eliminated a state that exec'ed out of module bounds unexpectedly
#     62 eliminated a state that exec'ed too many killable insns, possible hang or other unexpected error
#    128 eliminated a state that is at unexpected location
#      5 eliminated this false positive, execution path subset of another success
#      6 eliminated this false positive, out of range syscall number found at eip
#     15 State was terminated by opcode
#     13 wrong syscall found in memory range

foreach $key (sort keys %reasons) {
#$key, $value) = each (%reasons) ) {
   printf ("%7d", $reasons{$key});
   print " $key\n";
}

printf ("%7d Total\n", $tot);

#.*\'(.*)\'.*/\1/'
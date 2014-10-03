#! /usr/bin/perl -w

my $in = $ARGV[0];
if ($in eq "") {
   exit;
}

print "Ranking Termination Reasons from $in\n";   

my $success = 0;
# 1016 [State 1016] Terminating state 1016 with message 'eliminated a state that exec'ed out of module bounds unexpectedly'
my @msgs = `cat $in | grep "Term" | grep "with message" | sed -e "s/^.* '//" | sed -e "s/'\$//" | sort | uniq --count`;
my @msgs2 = ();
my $tot = 0;
foreach my $msg (@msgs) {
   $msg =~ m/^\s*(\d+)\s(.*$)/;
   my $cnt = $1;
   my $txt = $2;
   $tot += $cnt;
   # EIP reached, success
   # A syscall was accepted as valied, if EIP given then EIP reached; if syscall given, then was a match
   if ($txt =~ m/EIP reached, success/) {
      $msg =~ s/(^\s*\d+\s).*/$1Positive/;
      $msg2 = "Positive,$cnt\n";
      $success = 1;
   }
   # eliminated a state that exec'ed out of module bounds, in the kernel, for too long
   # Exec'ed in the kernel too long, exceeded MAX_KERN_INSNS
   elsif ($txt =~ m/module bounds, in the/) {
      $msg =~ s/(^\s*\d+\s).*/$1Runaway Kernel/;
      $msg2 = "Runaway Kernel,$cnt\n";
   }
   # eliminated a state that exec'ed out of module bounds unexpectedly
   # if was in range last insn, and now out of range, and we were not expecting to jmp OOB
   # aka An OOB insn occurred, but we weren't expecting one (each insn guesses the next insn and records if it will be OOB)
   elsif ($txt =~ m/module bounds unex/) {
      $msg =~ s/(^\s*\d+\s).*/$1Unexpected OOB Jump/;
      $msg2 = "Unexpected OOB Jump,$cnt\n";
   }
   # eliminated a state that exec'ed too many killable insns, possible hang or other unexpected error
   # Cummulative across all the other OOBs, generally execution control has been lost and will not return
   # other proc insns, kernel insns, out of range same proc insns. If that total > MAX_KILLABLE_INSNS
   elsif ($txt =~ m/too many killable/) {
      $msg =~ s/(^\s*\d+\s).*/$1Runaway Other/;
      $msg2 = "Runaway Other,$cnt\n";
   }
   # eliminated a state that is at unexpected location
   # Jumped to a place that was not predicted
   # if was in range last insns, and now out of range, and was expecting to jmp OOB, but this addr doesn't match was we predicted
   elsif ($txt =~ m/at unexpected loc/) {
      $msg =~ s/(^\s*\d+\s).*/$1Invalid OOB Jump/;
      $msg2 = "Invalid OOB Jump,$cnt\n";
   }
   # eliminated this false positive, execution path subset of another success
   # This positive is a suffix of a previous positive
   elsif ($txt =~ m/false positive, execution path subset/) {
      $msg =~ s/(^\s*\d+\s).*/$1FP Subset/;
      $msg2 = "FP Subset,$cnt\n";
   }
   # eliminated this false positive, out of range syscall number found at eip
   # This positive has a system call number > 256 
   elsif ($txt =~ m/false positive, out of range syscall/) {
      $msg =~ s/(^\s*\d+\s).*/$1FP Irregular EAX/;
      $msg2 = "FP Irregular EAX,$cnt\n";
   }
   # State was terminated by opcode
   # A fatal signal was caught, eg seg ill etc, so the signal handler killed the state 
   elsif ($txt =~ m/terminated by opcode/) {
      #$msg =~ s/(^\s*(\d+)\s).*/$1Opcode/;
      #$msg =~ m/^\s*(\d+)\s.*/;
      # one of these is the end of state0 after all calcs are complete
      $cnt--;
      $msg = sprintf ("%7d Fatal Signal OS\n", $cnt);
      $tot--;
      $msg2 = "Fatal Signal OS,$cnt\n";
   }
   # wrong syscall found in memory range
   # This system call was at the wrong EIP (and EIP was specified)
   elsif ($txt =~ m/wrong syscall found in memory range/) {
      $msg =~ s/(^\s*\d+\s).*/$1FP Wrong EIP/;
      $msg2 = "FP Wrong EIP,$cnt\n";
   }
   # eliminated a state with an impossible first instruction
   # The first insn is in a black list
   elsif ($txt =~ m/impossible first instruction/) {
      $msg =~ s/(^\s*\d+\s).*/$1Invalid First Insn/;
      $msg2 = "Invalid First Insn,$cnt\n";
   }
   # eliminated this false positive, incorrect syscall number found at eip
   # EAX was specified and it was wrong
   elsif ($txt =~ m/incorrect syscall number/) {
      $msg =~ s/(^\s*\d+\s).*/$1FP Wrong EAX/;
      $msg2 = "FP Wrong EAX,$cnt\n";
   }
   else {
      $msg = "Add a condition: $txt\n";
      $msg2 = "Add a condition\n";
   }
   print $msg;
   push @msgs2, $msg2;
}
printf ("%7d Total\n", $tot);
if (!$success) {
   print "NO SUCCESS\n";
}

print "\n";
@msgs2 = sort { $a cmp $b } @msgs2;
foreach my $msg (@msgs2) {
   print $msg;
}

#.*\'(.*)\'.*/\1/'
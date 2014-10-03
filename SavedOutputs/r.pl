#! /usr/bin/perl -w

my $in = $ARGV[0];
if ($in eq "") {
   exit;
}

print "Ranking Termination Reasons from $in\n";   

my $failed_constraint = 0;  # exec trace was a subset; wrong syscall number; out of range syscall; wrong eip; too short of bytes/insns
my $invalid_insn = 0;       # fatal signal from OS (seg, ill); blacklisted 1st insn; 
my $other_exec_failure = 0; # too many killable insns (kernel, OOB non-kernel, combined); no jump but at unexpected OOB insn; expected OOB jmp but at unexpected OOB insn;
my $success = 0;
# 1016 [State 1016] Terminating state 1016 with message 'eliminated a state that exec'ed out of module bounds unexpectedly'
my @msgs = `cat $in | grep "Term" | grep "with message" | sed -e "s/^.* '//" | sed -e "s/'\$//" | sort | uniq -c`;
my @msgs2 = ();
my $tot = 0;
foreach my $msg (@msgs) {
   $msg =~ m/^\s*(\d+)\s(.*$)/;
   my $cnt = $1;
   my $txt = $2;
   $tot += $cnt;
   # EIP reached, success
   # A syscall was accepted as valid, if EIP given then EIP reached; if syscall given, then was a match
   if ($txt =~ m/EIP reached, success/ || $txt =~/Success\/fragment found/) {
      $msg =~ s/(^\s*\d+\s).*/$1Fragment Found/;
      $msg2 = "Fragment Found,$cnt\n";
      $success = 1;
   }
   # eliminated a state that exec'ed out of module bounds, in the kernel, for too long
   # Exec'ed in the kernel too long, exceeded MAX_KERN_INSNS
   elsif ($txt =~ m/module bounds, in the/) {
      $msg =~ s/(^\s*\d+\s).*/$1Runaway Kernel/;
      $msg2 = "Runaway Kernel,$cnt\n";
      $other_exec_failure += $cnt;
   }
   # eliminated a state that exec'ed out of module bounds unexpectedly
   # if was in range last insn, and now out of range, and we were not expecting to jmp OOB
   # aka An OOB insn occurred, but we weren't expecting one (each insn guesses the next insn and records if it will be OOB)
   elsif ($txt =~ m/module bounds unex/) {
      $msg =~ s/(^\s*\d+\s).*/$1Unexpected OOB Insn/;
      $msg2 = "Unexpected OOB Insn,$cnt\n";
      $other_exec_failure += $cnt;
   }
   # eliminated a state that exec'ed too many killable insns, possible hang or other unexpected error
   # Cummulative across all the other OOBs, generally execution control has been lost and will not return
   # other proc insns, kernel insns, out of range same proc insns. If that total > MAX_KILLABLE_INSNS
   elsif ($txt =~ m/too many killable/) {
      $msg =~ s/(^\s*\d+\s).*/$1Runaway Other/;
      $msg2 = "Runaway Other,$cnt\n";
      $other_exec_failure += $cnt;
   }
   # eliminated a state that is at unexpected location
   # Jumped to a place that was not predicted
   # if was in range last insns, and now out of range, and was expecting to jmp OOB, but this addr doesn't match was we predicted
   elsif ($txt =~ m/at unexpected loc/) {
      $msg =~ s/(^\s*\d+\s).*/$1Invalid OOB Jump/;
      $msg2 = "Invalid OOB Jump,$cnt\n";
      $other_exec_failure += $cnt;
   }
   # eliminated this false positive, execution path subset of another success
   # This positive is a suffix of a previous positive
   elsif ($txt =~ m/false positive, execution path subset/) {
      $msg =~ s/(^\s*\d+\s).*/$1FP Subset/;
      $msg2 = "FP Subset,$cnt\n";
      $failed_constraint += $cnt;
   }
   # eliminated this false positive, out of range syscall number found at eip
   # This positive has a system call number > 256 
   elsif ($txt =~ m/false positive, out of range syscall/) {
      $msg =~ s/(^\s*\d+\s).*/$1FP Irregular EAX/;
      $msg2 = "FP Irregular EAX,$cnt\n";
      $failed_constraint += $cnt;
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
      $invalid_insn += $cnt;
   }
   # wrong syscall found in memory range
   # This system call was at the wrong EIP (and EIP was specified)
   elsif ($txt =~ m/wrong syscall found in memory range/) {
      $msg =~ s/(^\s*\d+\s).*/$1FP Wrong EIP/;
      $msg2 = "FP Wrong EIP,$cnt\n";
      $failed_constraint += $cnt;
   }
   # eliminated a state with an impossible first instruction
   # The first insn is in a black list
   elsif ($txt =~ m/impossible first instruction/) {
      $msg =~ s/(^\s*\d+\s).*/$1Invalid First Insn/;
      $msg2 = "Invalid First Insn,$cnt\n";
      $invalid_insn += $cnt;
   }
   # eliminated this false positive, incorrect syscall number found at eip
   # EAX was specified and it was wrong
   elsif ($txt =~ m/incorrect syscall number/) {
      $msg =~ s/(^\s*\d+\s).*/$1FP Wrong EAX/;
      $msg2 = "FP Wrong EAX,$cnt\n";
      $failed_constraint += $cnt;
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

my @times = `cat $in | grep "Message from" | sed -e "s/ .*//" | uniq `;
print "First timer: " . $times[0];
print "Last timer:  " . $times[$#times];
my $start_t = int ($times[0]);
my $end_t = int ($times[$#times]);
print "Difference:  " . ($end_t - $start_t) . "\n";
printf ("t (secs) / offset, tot: %.3f after activated: %.3f\n", $end_t/$tot, ($end_t-$start_t)/$tot );


print "\n";
my $term_tot = $failed_constraint + $invalid_insn + $other_exec_failure;
my $perc = $failed_constraint*100/$term_tot;
$perc =~ s/(\d*)\.(\d\d\d\d).*/$1.$2/;
print "Failed Constraint,$failed_constraint $perc\%\n";
$perc = $invalid_insn*100/$term_tot;
$perc =~ s/(\d*)\.(\d\d\d\d).*/$1.$2/;
print "Invalid Instruction,$invalid_insn  $perc\%\n";
$perc = $other_exec_failure*100/$term_tot;
$perc =~ s/(\d*)\.(\d\d\d\d).*/$1.$2/;
print "Other Exec Failure,$other_exec_failure  $perc\%\n";
print "\n";
@msgs2 = sort { $a cmp $b } @msgs2;
foreach my $msg (@msgs2) {
   print $msg;
}

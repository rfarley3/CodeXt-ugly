#! /usr/bin/perl -w

use strict;

my @in = ();

if ($#ARGV < 0) {
   print "Gimme an 8b integer in decimal, hex, octal, or binary: ";
   my $num = <STDIN>;
   chomp $num;
   exit unless defined $num;
   push @in, $num;
}
else {
   print "Up to you to make sure input is only 8b\n";
   foreach my $arg (@ARGV) {
      push @in, $arg;
   }
}

my $is_4B = 0;
my $saw_4B = 0;
my $tot = 0;
foreach my $n (@in) {
   my ($d, $i, $h, $b);
   $is_4B = 0;
   if ($n =~ /^0b/) {
      #print "0:$n\n";
      my $len = length ($n);
      while ($len < 10) {
         $n =~ s/^0b/0b0/;
         $len++;
      }
      $b = $n;
      $h = sprintf "%x", oct ($n);
      if (length ($h) < 2) {
         $h = "0" . $h;
      }
      $h = "0x$h";
      #print "1:$b,$h\n";
      if ($n =~ /^0b1/) {
         $n =~ s/^0b1/0b0/;
         $i = sprintf "%d", (-128 + oct ($n) );
      }
      else {
         $i = sprintf "%d", oct ($n);
      }
      #print "2:$b,$h,$i\n";
      $d = $i;
   }
   elsif ($n =~ /^0x/) {
      my $len = length ($n);
     if ($len <= 4) {
      while ($len < 4) {
         $n =~ s/^0x/0x0/;
         $len++;
      }
      $h = $n;
      $b = sprintf "%#b", (oct ($n) & 0xff);
      $len = length ($b);
      while ($len < 10) {
         $b =~ s/^0b/0b0/;
         $len++;
      }
      if ($b =~ /^0b1/) {
         $n = $b;
         $n =~ s/^0b1/0b0/;
         $i = sprintf "%d", (-128 + oct ($n) );
      }
      else {
         $i = sprintf "%d", oct ($b);
      }
      $d = $i;
     }
     else { # 4B
         $is_4B = 1;
         $saw_4B = 1;
         while ($len < 10) {
             $n =~ s/^0x/0x0/;
             $len++;
          }
          $h = $n;
          $b = sprintf "%#b", (oct ($n) & 0xffffffff);
          $len = length ($b);
          while ($len < 34) {
             $b =~ s/^0b/0b0/;
             $len++;
          }
          if ($b =~ /^0b1/) {
             $n = $b;
             $n =~ s/^0b1/0b0/; 
             $i = sprintf "%d", (-2147483648 + oct ($n) );
          }
          else {
             $i = sprintf "%d", oct ($b);
          }
          $d = $i;
     }
   }
   else {
      $d = $i = $n;
      $b = sprintf "%#b", $n & 0xff;
      my $len = length ($b);
      while ($len < 10) {
         $b =~ s/^0b/0b0/;
         $len++;
      }
      $h = sprintf "%#x", $n & 0xff;
      $len = length ($h);
      while ($len < 4) {
         $h =~ s/^0x/0x0/;
         $len++;
      }
   }
   printf "  >> %11d $h", $d;
   if ($is_4B == 0) {
      printf "      ";
   }
   printf " $b\n";
   #printf "%d %#x %#o %#b\n", ($n) x 4;
   $tot += $d;
}
printf "tot> %11d", $tot;
my $h = sprintf "%#x", ($tot & 0xff);
if ($saw_4B) {
   $h = sprintf "%#x", ($tot & 0xffffffff);
}
my $len = length ($h);
while ($len < 4) {
   $h =~ s/^0x/0x0/;
   $len++;
}
if ($saw_4B) {
   while ($len < 10) {
      $h =~ s/^0x/0x0/;
      $len++;
   }
}
my $b = sprintf "%#b", ($tot & 0xff);
if ($saw_4B) {
   $b = sprintf "%#b", ($tot & 0xffffffff);
}
$len = length ($b);
while ($len < 10) {
   $b =~ s/^0b/0b0/;
   $len++;
}
if ($saw_4B) {
   while ($len < 34) {
      $b =~ s/^0b/0b0/;
      $len++;
   }
}
printf " $h ";
if ($saw_4B == 0) {
   printf "      ";
}
printf "$b\n";

exit;

# end file

#! /usr/bin/perl -w

my $old = "/home/s2e/s2e/build";
my $old_root = "/home/s2e";
my $new_root = "/mnt/RJFDasos";
@files = `find $old -type l -print`;

foreach my $file (@files) {
   print $file;
   my $symlink = `ls -al $file`;
   #print $symlink;
   $symlink =~ s/^[^\/]*//;
   print $symlink;
   $symlink =~ s/(.*)->(.*)/$2 $1/;
   #print $symlink;
   my $old_file = $1;
   $old_file =~ s/^\s*//;
   $old_file =~ s/\s*$//;
   if (-e $old_file) {
      $symlink =~ s/$old_root/$new_root/g;
      my $new_file = $symlink;
      #print "1" . $new_file;
      #/mnt/RJFDasos/s2e/s2e/qemu/roms/s2ebios/Makefile /mnt/RJFDasos/s2e/build/qemu-release/roms/s2ebios/Makefile
      $new_file =~ s/^\s*//;
      $new_file =~ s/([^\s]*)\s.*$/$1/;
      #print "2" . $new_file;
      $new_file =~ s/\s*$//;
      #print "3" . $new_file;
      if (-e $new_file) {
         my $cmd = "ln -s $symlink";
         my $out = `$cmd`;
         print "$cmd : $out";
         #rsync -av --files-from=- /home/s2e/s2e/build /mnt/RJFDasos/s2e/build
      }
      else {
         print "!!! new file ($new_file) does not exist\n";
      }
   }
   else {
      print "!!! old file ($old_file) does not exist\n";
   }

}

exit;

#!!! new file (../s2e/Makefile) does not exist
#/home/s2e/s2e/build/Makefile -> ../s2e/Makefile, so manually run ln -s /mnt/RJFDasos/s2e/s2e/Makefile /mnt/RJFDasos/s2e/build/Makefile
#!!! old file (/home/s2e/s2e/build/qemu-release/roms/vgabios/Makefile) does not exist
#!!! old file (/home/s2e/s2e/build/qemu-release/roms/seabios/Makefile) does not exist
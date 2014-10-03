#! /bin/sh

ORIG=/home/s2e/s2e/s2e
MOD=/home/s2e/s2e/dasos/s2e/s2e

#diff -Naur $OLD $NEW > RJF_patch_file
#!/bin/bash

#USAGE="USAGE: $0 <dist dir> <edited dir>"

# trim starting './' and trailing /'/
#original=$(echo $1 | sed 's-^\./--;s-/$--')
#changed=$(echo $2 | sed 's-^\./--;s-/$--')

[ -d $ORIG ] || { echo "ERROR: Directory $ORIG does not exist" >&2 ; exit 2; }
[ -d $MOD ] || { echo "ERROR: Directory $MOD does not exist" >&2; exit 3; }

cd $ORIG
#command="ls -l"
command="diff -Naur"

for file in `find -name '*.[ch]' -o -name '*.cpp'`
do
  #| { while read file; do echo "$command $OLD/$file $NEW/$file"; done; }
  #echo "$command $ORIG/$file $MOD/$file"
  $command $ORIG/$file $MOD/$file
done
#find $ORIG -name '*.[ch]' -o -name '*.cpp' | sed 's/^$ORIG//'
# | { while read file; do $command $ORIG/$file $MOD/$file; done; }
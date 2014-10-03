#! /usr/bin/env python

import os

SYSCALLLIST="/usr/include/bits/syscall.h"



phil:~/work/prog/python/shellforge$ awk  '/define.*NR/{print substr($2,6)}' include/sfsyscall.h | while read a; do b=/usr/share/man/man2/$a.2.gz;  [ -e "$b" ] && zgrep " $a(.*;$" $b; done | perl -pe 's/(.BI?|\\f.|"|;$)/ /g'

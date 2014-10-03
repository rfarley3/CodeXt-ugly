#! /bin/sh

S2ESRC=/home/s2e/s2e/dasos/s2e/.

grep -n --color -R "$1" $S2ESRC --include "*.h"  --include "*.cpp" --include "*.c"

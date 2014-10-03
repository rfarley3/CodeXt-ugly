#! /bin/sh
# 15 Aug 2012 RJF

S2EBUILD=/home/s2e/s2e/dasos/s2e/build
S2ESRC=/home/s2e/s2e/dasos/s2e/s2e

# To build S2E with the plugin
#cp <Plugin code> $S2ESRC/qemu/s2e/Plugins/.
#vi $S2ESRC/qemu/Makefile.target and at line 483 add:
## RJF, put in custom plugins here
#s2eobj-y += s2e/Plugins/InstructionTracker.o
## end RJF

cd $S2EBUILD
make


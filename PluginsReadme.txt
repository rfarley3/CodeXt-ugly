# 26 July RJF

Develop plugins here (/home/s2e/<somewhere>)

S2ESRC=/usr/local/src/s2e/s2e
S2EBUILD=/usr/local/src/s2e/build

# To build S2E with the plugin
cp <Plugin code> $S2ESRC/qemu/s2e/Plugins/.
vi $S2ESRC/qemu/Makefile.target and at line 483 add:
# RJF, put in custom plugins here
s2eobj-y += s2e/Plugins/InstructionTracker.o
# end RJF
<<EOF
cd $S2EBUILD
make

# Verify that QEMU works in vanilla mode
$S2EBUILD/qemu-release/i386-softmmu/qemu-system-i386 -m 8
# you should see BIOS booting in the VM

# Verify that QEMU works in S2E mode
$S2EBUILD/qemu-release/i386-s2e-softmmu/qemu-system-i386 -m 8
# you should see BIOS booting in the VM


To run the plugin you need to give s2e a configuration file; use the CLA: -s2e-config-file <config file name>.lua

A config file looks like:

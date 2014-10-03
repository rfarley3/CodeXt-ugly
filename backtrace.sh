#! /bin/sh

PROG=/home/s2e/s2e/dasos/s2e/build/qemu-release/i386-s2e-softmmu/qemu
CORE=core

gdb -q -n -ex bt -batch $PROG $CORE

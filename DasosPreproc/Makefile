# RJF 08/2012

# Makefile for DASoS Preprocessor S2E Plugin Development
S2E_BUILD_DIR=/home/s2e/s2e/dasos/s2e/build
S2E_SRC_DIR=/home/s2e/s2e/dasos/s2e/s2e
PLUGINS_DIR=${S2E_SRC_DIR}/qemu/s2e/Plugins
QEMU_BUILD_DIR=/home/s2e/s2e/dasos/s2e/build/qemu-release
S2E_QEMU_BIN=${QEMU_BUILD_DIR}/i386-s2e-softmmu/qemu
QEMU_BIN=${QEMU_BUILD_DIR}/i386-softmmu/qemu
UNTOUCHED_S2E_QEMU_BIN=/home/s2e/s2e/build/qemu-release/i386-s2e-softmmu/qemu

DISKIMG_DIR=/home/s2e/s2e/dasos/DiskImgs
DEVEL_DIR=/home/s2e/s2e/dasos/DasosPreproc
STAMPS_DIR=${DEVEL_DIR}/mk.stamps
#CONF_FILE=conf-SyscallTracker.lua
CONF_FILE=conf-DasosPreproc.lua
DISKIMG=s2e-waiting.qcow2
SAVED_STATE=s2e-waiting

CC32=gcc -Wall -g -m32

default: help

help:
	@echo "Makefile for DASoS Preprocessor S2E Plugin Development"
	@echo "\thelp:\t\tThis output"
	@echo "\tinfo:\t\tShow last ran timestamps for the make stamps"
	@echo "\tpublish:\tPush S2E plugin sourcecode into S2E plugin sourcetree"
	@echo "\tbuild-test:\tPublish && build only the S2E Plugin Sourcetree"
	@echo "\t\tNote: S2E plugins' Makefile.target must be editted appropriately"
# double check Plugin.cpp and the plugindir/Makefile.target (both compiling and linking sections)
	@echo "\tbuild:\t\tPublish && and build entire S2E QEMU"
	@echo "\ttest:\t\tBuild && Run S2E QEMU to see if it boots"
	@echo "\trun-nons2e:\tRun QEMU without S2E: quicker boot for setting up s2eget"
	@echo "\trun:\t\tResumes a saved state executing s2eget and runs test"
	@echo "\t\tNote: To see the plugin output, run: tail -f s2e-last/debug.txt"

${STAMPS_DIR}/mk.publish-Int: Given-Code/InterruptMonitor.cpp Given-Code/InterruptMonitor.h
	@cp -vu Given-Code/InterruptMonitor.cpp ${PLUGINS_DIR}/.
	@cp -vu Given-Code/InterruptMonitor.h ${PLUGINS_DIR}/.
	touch ${STAMPS_DIR}/$@

${STAMPS_DIR}/mk.publish-LSys: Given-Code/LinuxSyscallMonitor.cpp Given-Code/LinuxSyscallMonitor.h
	@cp -vu Given-Code/LinuxSyscallMonitor.cpp ${PLUGINS_DIR}/.
	@cp -vu Given-Code/LinuxSyscallMonitor.h ${PLUGINS_DIR}/.
	touch ${STAMPS_DIR}/$@

${STAMPS_DIR}/mk.publish-SysT: Given-Code/SyscallTracker.cpp Given-Code/SyscallTracker.h
	@cp -vu Given-Code/SyscallTracker.cpp ${PLUGINS_DIR}/.
	@cp -vu Given-Code/SyscallTracker.h ${PLUGINS_DIR}/.
	@cp -vu Given-Code/syscallent-simple.h ${PLUGINS_DIR}/.
	touch ${STAMPS_DIR}/$@

${STAMPS_DIR}/mk.publish-DPre: DasosPreproc.cpp DasosPreproc.h
	@cp -vu DasosPreproc.cpp ${PLUGINS_DIR}/.
	@cp -vu DasosPreproc.h ${PLUGINS_DIR}/.
	touch ${STAMPS_DIR}/$@

${STAMPS_DIR}/mk.publish-mkfiletarget: ../Plugins-Makefile.target
	@cp -vu ../Plugins-Makefile.target ${S2E_SRC_DIR}/qemu/Makefile.target
	touch ${STAMPS_DIR}/$@

${STAMPS_DIR}/mk.publish-execall: ../qemu-exec-all.h
	@cp -vu ../qemu-exec-all.h ${S2E_SRC_DIR}/qemu/exec-all.h
	touch ${STAMPS_DIR}/$@

${STAMPS_DIR}/mk.publish-plugincpp: ../Plugins-Plugin.cpp
	@cp -vu ../Plugins-Plugin.cpp ${S2E_SRC_DIR}/qemu/s2e/Plugin.cpp
	touch ${STAMPS_DIR}/$@

${STAMPS_DIR}/mk.publish-opcodes: ../Plugins-Opcodes.h
	@cp -vu ../Plugins-Opcodes.h ${S2E_SRC_DIR}/qemu/s2e/Plugins/Opcodes.h
	touch ${STAMPS_DIR}/$@

${STAMPS_DIR}/mk.publish-traceents: ../ExecutionTracers-TraceEntries.h
	@cp -vu ../ExecutionTracers-TraceEntries.h ${S2E_SRC_DIR}/qemu/s2e/Plugins/ExecutionTracers/TraceEntries.h
	touch ${STAMPS_DIR}/$@

${STAMPS_DIR}/mk.publish-translate: ../i386-translate.c
	@cp -vu ../i386-translate.c ${S2E_SRC_DIR}/qemu/target-i386/translate.c
	touch ${STAMPS_DIR}/$@

${STAMPS_DIR}/mk.publish-s2eh: ../guestinclude-s2e.h
	@cp -vu ../guestinclude-s2e.h ${S2E_SRC_DIR}/guest/include/s2e.h
	touch ${STAMPS_DIR}/$@

${STAMPS_DIR}/mk.publish: ${STAMPS_DIR}/mk.publish-Int ${STAMPS_DIR}/mk.publish-LSys ${STAMPS_DIR}/mk.publish-SysT ${STAMPS_DIR}/mk.publish-DPre ${STAMPS_DIR}/mk.publish-mkfiletarget ${STAMPS_DIR}/mk.publish-execall ${STAMPS_DIR}/mk.publish-plugincpp ${STAMPS_DIR}/mk.publish-opcodes ${STAMPS_DIR}/mk.publish-traceents ${STAMPS_DIR}/mk.publish-translate ${STAMPS_DIR}/mk.publish-s2eh
	@echo "Published files"
	touch ${STAMPS_DIR}/$@

publish: ${STAMPS_DIR}/mk.publish

${STAMPS_DIR}/mk.build-test: ${STAMPS_DIR}/mk.publish
	@echo "First compiling the plugins directory only, to save time if debugging errors"
	${MAKE} -C ${S2E_BUILD_DIR}/qemu-release VERBOSE=1
	touch ${STAMPS_DIR}/$@

build-test: ${STAMPS_DIR}/mk.build-test

${STAMPS_DIR}/mk.build: ${STAMPS_DIR}/mk.publish ${STAMPS_DIR}/mk.build-test
	@echo "Building the S2E version of QEMU"
	${MAKE} -C ${S2E_BUILD_DIR}
	touch ${STAMPS_DIR}/$@

build: ${STAMPS_DIR}/mk.build

${STAMPS_DIR}/mk.test: ${STAMPS_DIR}/mk.build
	@echo "Testing S2E with Plugins, but without a HDD. Success if reaches a No bootable device output"
	${S2E_QEMU_BIN} -m 8 -s2e-config-file ${DEVEL_DIR}/${CONF_FILE}
	touch ${STAMPS_DIR}/$@

test: ${STAMPS_DIR}/mk.test


${STAMPS_DIR}/mk.run-nons2e: ${STAMPS_DIR}/mk.build
# 	@echo "Running QEMU without S2E, for either sanity check or for a quicker boot (once up run s2eget, save state, and suspend)"
	@echo "Note that S2E can distort qcows after a while, so use the raw disk image every now and again to set things up fresh"
	@echo "Are you sure that you want to do this? Press enter to continue or CTRL+C to exit."
	@read abc
	#${QEMU_BINPATH} -hda ${DISKIMG_DIR}s2e_disk2.raw -redir tcp:2222::22
	${QEMU_BIN} -hda ${DISKIMG_DIR}/${DISKIMG} -redir tcp:2222::22
	touch ${STAMPS_DIR}/$@

run-nons2e: ${STAMPS_DIR}/mk.run-nons2e


${STAMPS_DIR}/mk.shellcode-wrapper: shellcode-wrapper/libDasosfDump.c shellcode-wrapper/libDasosfDump.h shellcode-wrapper/shellcode-wrapper.c
	make -C shellcode-wrapper
	touch ${STAMPS_DIR}/$@

${STAMPS_DIR}/mk.stubs: stubs/stub-symb-iteration.c
	make -C stubs
	touch ${STAMPS_DIR}/$@


#dasosfDumpPrint: libDasosfDump.o libDasosBastard.o dasosfDumpPrint.c
#$(CC) -o dasosfDumpPrint -ldisasm dasosfDumpPrint.c libDasosfDump.o libDasosBastard.o

${STAMPS_DIR}/mk.prep-hostfiles: ${STAMPS_DIR}/mk.shellcode-wrapper firstRan.sh ${STAMPS_DIR}/mk.stubs
	@echo "Preparing the HostFiles directory"
	rm ${DEVEL_DIR}/runtime.dir/*
	@cp -vu stubs/stub-symb-iteration ${DEVEL_DIR}/runtime.dir/.
	@cp -vu shellcode-wrapper/shellcode-wrapper  ${DEVEL_DIR}/runtime.dir/.
	@cp -vu firstRan.sh  ${DEVEL_DIR}/runtime.dir/.
	mv ${DEVEL_DIR}/HostFiles/pkg.tar ${DEVEL_DIR}/HostFiles/pkg.tar.old
	tar cvf ${DEVEL_DIR}/HostFiles/pkg.tar runtime.dir/*
	touch ${STAMPS_DIR}/$@

${STAMPS_DIR}/mk.tut1-prep-hostfiles: firstRan.sh-tut1 tutorial1
	@echo "Preparing the HostFiles directory"
	rm ${DEVEL_DIR}/runtime.dir/*
	@cp -vu tutorial1 ${DEVEL_DIR}/runtime.dir/.
	@cp -vu firstRan.sh-tut1 ${DEVEL_DIR}/runtime.dir/firstRan.sh
	mv ${DEVEL_DIR}/HostFiles/pkg.tar ${DEVEL_DIR}/HostFiles/pkg.tar.old
	tar cvf ${DEVEL_DIR}/HostFiles/pkg.tar runtime.dir/*
	touch ${STAMPS_DIR}/$@


# QEMU requires a properly windowed environment, so you can not run it over SSH X sessions: if you do, then you will receive an error about SDL.
${STAMPS_DIR}/mk.run: ${STAMPS_DIR}/mk.prep-hostfiles ${STAMPS_DIR}/mk.build
	@echo "Resuming the VM (waiting with s2eget) for a test"
	${S2E_QEMU_BIN} -s2e-config-file ${DEVEL_DIR}/${CONF_FILE} -hda ${DISKIMG_DIR}/${DISKIMG} -redir tcp:2222::22 -loadvm ${SAVED_STATE}
	touch ${STAMPS_DIR}/$@
	@echo "To see the output of the plugin run: tail -f s2e-last/debug.txt"

# if you don't delete the stamp, then make will claim there is nothing to do for run
del-mk.run:
	@rm -f ${STAMPS_DIR}/mk.run

run: del-mk.run ${STAMPS_DIR}/mk.run


tutorial1: tutorial1.c
	gcc -m32 -O3 tutorial1.c -o tutorial1


${STAMPS_DIR}/mk.tut1-run: ${STAMPS_DIR}/mk.tut1-prep-hostfiles ${STAMPS_DIR}/mk.build # no need for ${STAMPS_DIR}/mk.build if you're using the untouched s2e binary
#${STAMPS_DIR}/mk.tut1-run: ${STAMPS_DIR}/mk.tut1-prep-hostfiles
	@echo "Resuming the VM (waiting with s2eget) to run the tutorial1 code"
	#${UNTOUCHED_S2E_QEMU_BIN} -s2e-config-file ${DEVEL_DIR}/tutorial1.lua -hda ${DISKIMG_DIR}/${DISKIMG} -redir tcp:2222::22 -loadvm ${SAVED_STATE} -s2e-verbose
	${S2E_QEMU_BIN} -s2e-config-file ${DEVEL_DIR}/tutorial1.lua -hda ${DISKIMG_DIR}/${DISKIMG} -redir tcp:2222::22 -loadvm ${SAVED_STATE} -s2e-verbose
	touch ${STAMPS_DIR}/$@
	@echo "To see the output of the plugin run: tail -f s2e-last/debug.txt"
	
del-mk.tut1-run:
	@rm -f ${STAMPS_DIR}/mk.tut1-run

tut1-run: del-mk.tut1-run ${STAMPS_DIR}/mk.tut1-run


observe:
	tail -f ${DEVEL_DIR}/s2e-last/debug.txt 


info:
	@echo "The following is a record of the last known timestamps (e.g. when the various build stages were ran last). The build stages, in order or dependencies, are: publish-*; publish; build-test; build; (test | run-nons2e | (prep-hostfiles; run))"
	@ls -logt ${STAMPS_DIR}/mk.* | awk '{print $$4,$$5,$$6}' | sed 's\${STAMPS_DIR}/mk.\\' | sed 's\/.*/\\'
	@echo "Current time is:"
	@date "+%Y-%m-%d %H:%M"

tidy:
	rm -f *~

clean:
	rm -f *.o
	
tidyouts:
	rm -Rf s2e-out-*

# running this will cause next make to redo everything
cleanstamps:
	rm -f ${STAMPS_DIR}/mk.*

#cleanall: tidy cleanobjs tidyouts

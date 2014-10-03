# RJF 08/2012

# Makefile for DASoS Preprocessor S2E Plugin Development
S2E_BUILD_DIR=/home/s2e/s2e/dasos/s2e/build
S2E_SRC_DIR=/home/s2e/s2e/dasos/s2e/s2e
UNTOUCHED_S2E_SRC_DIR=/home/s2e/s2e/s2e
PLUGINS_DIR=${S2E_SRC_DIR}/qemu/s2e/Plugins
QEMU_BUILD_DIR=${S2E_BUILD_DIR}/qemu-release
S2E_QEMU_BIN=${QEMU_BUILD_DIR}/i386-s2e-softmmu/qemu
QEMU_BIN=${QEMU_BUILD_DIR}/i386-softmmu/qemu
UNTOUCHED_S2E_QEMU_BIN=/home/s2e/s2e/build/qemu-release/i386-s2e-softmmu/qemu

DISKIMG_DIR=/home/s2e/s2e/dasos/DiskImgs
DEVEL_DIR=/home/s2e/s2e/dasos
STAMPS_DIR=${DEVEL_DIR}/mk.stamps
CONF_FILE=conf-CodeXt.lua
DISKIMG=s2e-waiting.qcow2
SAVED_STATE=s2e-waiting

TCP_REDIR=-redir tcp:2222::22 -redir tcp:10000::10000 

CC=gcc -Wall -g 
CC32=${CC} -m32
DIFF=diff -uN
DIFF_END= || echo 'Files differ'

default: help

help:
	@echo "Makefile for DASoS Preprocessor S2E Plugin Development"
	@echo "\thelp:\t\tThis output"
	@echo "\tinfo:\t\tShow last ran timestamps for the make stamps"
	@echo "\tbackup:\tBack up all code to the host rw directory"
	@echo "\tpublish:\tPush developed sourcecode into S2E plugin sourcetree"
	@echo "\tbuild-test:\tPublish && build only the S2E Plugin Sourcetree"
	@echo "\t\tNote: S2E plugins' Makefile.target must be edited appropriately"
# double check Plugin.cpp and the plugindir/Makefile.target (both compiling and linking sections)
	@echo "\tbuild:\t\tPublish && and build entire S2E QEMU"
	@echo "\ttest:\t\tBuild && Run S2E QEMU to see if it boots"
	@echo "\trun-nons2e:\tRun QEMU without S2E: quicker boot for setting up s2eget"
	@echo "\trun:\t\tResumes a saved state executing s2eget and runs test"
	@echo "\t\tNote: To see the plugin output, run: tail -f s2e-last/debug.txt"
	@echo "\tdiff:\t\tGenerates a diff file between the edited S2E src files and their originals"

${STAMPS_DIR}/mk.backup:
	@echo "Backing up to Host Shared Folder"
	time rsync -rptv --exclude=core /mnt/RJFDasos/* /mnt/hgfs/hostrw/Attempt3/.
	@echo ""
	@echo "Backing up to Remote File Server"
	time rsync -rptv --exclude=core --exclude=s2e-out* --exclude=*.qcow2 /mnt/RJFDasos/* rfarley3@10.0.1.254:/mnt/gmu.backup/S2E-CodeXt-dirty/.
	@echo ""
	@echo "Reminder, these backups are non-deleting, and grow unkempt, use rsnapshot with the external drive for cleaner periodic backups. This VM will auto-connect the 1TB Seagate and has an fstab entry for it at /mnt/local.backup"
	@echo "E.g. For clean dailies: sudo ${DEVEL_DIR}/dailyCommit.sh"
	@echo "E.g. For quick (unclean): sudo ${DEVEL_DIR}/dirtyCommit.sh"
	touch $@

del-mk.backup:
	@rm -f ${STAMPS_DIR}/mk.backup

backup: del-mk.backup ${STAMPS_DIR}/mk.backup

${STAMPS_DIR}/mk.publish-Int: Given-Code/InterruptMonitor.cpp Given-Code/InterruptMonitor.h
	@cp -vu Given-Code/InterruptMonitor.cpp ${PLUGINS_DIR}/.
	@cp -vu Given-Code/InterruptMonitor.h ${PLUGINS_DIR}/.
	touch $@

${STAMPS_DIR}/mk.publish-LSys: Given-Code/LinuxSyscallMonitor.cpp Given-Code/LinuxSyscallMonitor.h
	@cp -vu Given-Code/LinuxSyscallMonitor.cpp ${PLUGINS_DIR}/.
	@cp -vu Given-Code/LinuxSyscallMonitor.h ${PLUGINS_DIR}/.
	touch $@

${STAMPS_DIR}/mk.publish-SysT: Given-Code/SyscallTracker.cpp Given-Code/SyscallTracker.h
	@cp -vu Given-Code/SyscallTracker.cpp ${PLUGINS_DIR}/.
	@cp -vu Given-Code/SyscallTracker.h ${PLUGINS_DIR}/.
	@cp -vu Given-Code/syscallent-simple.h ${PLUGINS_DIR}/.
	touch $@

${STAMPS_DIR}/mk.publish-CodeXt: CodeXt/CodeXt.cpp CodeXt/CodeXt.h
	@cp -vu CodeXt/CodeXt.cpp ${PLUGINS_DIR}/.
	@cp -vu CodeXt/CodeXt.h ${PLUGINS_DIR}/.
	touch $@
	
pub:
	@cp -v CodeXt/CodeXt.cpp ${PLUGINS_DIR}/.
	@cp -v CodeXt/CodeXt.h ${PLUGINS_DIR}/.

${STAMPS_DIR}/mk.publish-mkfiletarget: EditedS2ESrcFiles/Plugins-Makefile.target
	@cp -vu EditedS2ESrcFiles/Plugins-Makefile.target ${S2E_SRC_DIR}/qemu/Makefile.target
	touch $@

${STAMPS_DIR}/mk.diff-mkfiletarget: EditedS2ESrcFiles/Plugins-Makefile.target
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/qemu/Makefile.target EditedS2ESrcFiles/Plugins-Makefile.target > EditedS2ESrcFiles/diff.Plugins-Makefile.target ${DIFF_END}
	touch $@

${STAMPS_DIR}/mk.publish-execall: EditedS2ESrcFiles/qemu-exec-all.h
	@cp -vu EditedS2ESrcFiles/qemu-exec-all.h ${S2E_SRC_DIR}/qemu/exec-all.h
	touch $@

${STAMPS_DIR}/mk.diff-execall: EditedS2ESrcFiles/qemu-exec-all.h
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/qemu/exec-all.h EditedS2ESrcFiles/qemu-exec-all.h > EditedS2ESrcFiles/diff.qemu-exec-all.h ${DIFF_END}
	touch $@

${STAMPS_DIR}/mk.publish-coreplugin: EditedS2ESrcFiles/Plugins-Coreplugin.cpp EditedS2ESrcFiles/Plugins-Coreplugin.h 
	@cp -vu EditedS2ESrcFiles/Plugins-Coreplugin.cpp ${S2E_SRC_DIR}/qemu/s2e/Plugins/CorePlugin.cpp
	@cp -vu EditedS2ESrcFiles/Plugins-Coreplugin.h ${S2E_SRC_DIR}/qemu/s2e/Plugins/CorePlugin.h
	touch $@

${STAMPS_DIR}/mk.diff-coreplugin: EditedS2ESrcFiles/Plugins-Coreplugin.cpp EditedS2ESrcFiles/Plugins-Coreplugin.h
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/qemu/s2e/Plugins/CorePlugin.cpp EditedS2ESrcFiles/Plugins-Coreplugin.cpp > EditedS2ESrcFiles/diff.Plugins-Coreplugin.cpp ${DIFF_END}
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/qemu/s2e/Plugins/CorePlugin.h EditedS2ESrcFiles/Plugins-Coreplugin.h > EditedS2ESrcFiles/diff.Plugins-Coreplugin.h ${DIFF_END}
	touch $@

${STAMPS_DIR}/mk.publish-s2eqemuh: EditedS2ESrcFiles/Main-s2e_qemu.h
	cp EditedS2ESrcFiles/Main-s2e_qemu.h ${S2E_SRC_DIR}/qemu/s2e/s2e_qemu.h
	touch $@

${STAMPS_DIR}/mk.diff-s2eqemuh: EditedS2ESrcFiles/Main-s2e_qemu.h
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/qemu/s2e/s2e_qemu.h EditedS2ESrcFiles/Main-s2e_qemu.h > EditedS2ESrcFiles/diff.Main-s2e_qemu.h ${DIFF_END}
	touch $@

${STAMPS_DIR}/mk.publish-plugincpp: EditedS2ESrcFiles/Plugins-Plugin.cpp
	@cp -vu EditedS2ESrcFiles/Plugins-Plugin.cpp ${S2E_SRC_DIR}/qemu/s2e/Plugin.cpp
	touch $@

${STAMPS_DIR}/mk.diff-plugincpp: EditedS2ESrcFiles/Plugins-Plugin.cpp
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/qemu/s2e/Plugin.cpp EditedS2ESrcFiles/Plugins-Plugin.cpp > EditedS2ESrcFiles/diff.Plugins-Plugin.cpp ${DIFF_END}
	touch $@

${STAMPS_DIR}/mk.publish-opcodes: EditedS2ESrcFiles/Plugins-Opcodes.h
	@cp -vu EditedS2ESrcFiles/Plugins-Opcodes.h ${S2E_SRC_DIR}/qemu/s2e/Plugins/Opcodes.h
	touch $@

${STAMPS_DIR}/mk.diff-opcodes: EditedS2ESrcFiles/Plugins-Opcodes.h
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/qemu/s2e/Plugins/Opcodes.h EditedS2ESrcFiles/Plugins-Opcodes.h > EditedS2ESrcFiles/diff.Plugins-Opcodes.h ${DIFF_END}
	touch $@

${STAMPS_DIR}/mk.publish-traceents: EditedS2ESrcFiles/ExecutionTracers-TraceEntries.h
	@cp -vu EditedS2ESrcFiles/ExecutionTracers-TraceEntries.h ${S2E_SRC_DIR}/qemu/s2e/Plugins/ExecutionTracers/TraceEntries.h
	touch $@

${STAMPS_DIR}/mk.diff-traceents: EditedS2ESrcFiles/ExecutionTracers-TraceEntries.h
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/qemu/s2e/Plugins/ExecutionTracers/TraceEntries.h EditedS2ESrcFiles/ExecutionTracers-TraceEntries.h > EditedS2ESrcFiles/diff.ExecutionTracers-TraceEntries.h ${DIFF_END}
	touch $@

${STAMPS_DIR}/mk.publish-translate: EditedS2ESrcFiles/i386-translate.c
	@cp -vu EditedS2ESrcFiles/i386-translate.c ${S2E_SRC_DIR}/qemu/target-i386/translate.c
	touch $@

${STAMPS_DIR}/mk.diff-translate: EditedS2ESrcFiles/i386-translate.c
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/qemu/target-i386/translate.c EditedS2ESrcFiles/i386-translate.c > EditedS2ESrcFiles/diff.i386-translate.c ${DIFF_END}
	touch $@

${STAMPS_DIR}/mk.publish-s2eh: EditedS2ESrcFiles/guestinclude-s2e.h
	@cp -vu EditedS2ESrcFiles/guestinclude-s2e.h ${S2E_SRC_DIR}/guest/include/s2e.h
	touch $@

${STAMPS_DIR}/mk.diff-s2eh: EditedS2ESrcFiles/guestinclude-s2e.h
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/guest/include/s2e.h EditedS2ESrcFiles/guestinclude-s2e.h > EditedS2ESrcFiles/diff.guestinclude-s2e.h ${DIFF_END}
	touch $@

${STAMPS_DIR}/mk.publish-kleeexecutor: EditedS2ESrcFiles/klee-Executor.cpp EditedS2ESrcFiles/klee-Executor.h
	@cp -vu EditedS2ESrcFiles/klee-Executor.cpp ${S2E_SRC_DIR}/klee/lib/Core/Executor.cpp
	@cp -vu EditedS2ESrcFiles/klee-Executor.h ${S2E_SRC_DIR}/klee/include/klee/Executor.h
	touch $@
					 
${STAMPS_DIR}/mk.diff-kleeexecutor: EditedS2ESrcFiles/klee-Executor.cpp
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/klee/lib/Core/Executor.cpp EditedS2ESrcFiles/klee-Executor.cpp > EditedS2ESrcFiles/diff.kleeexecutor.cpp ${DIFF_END}
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/klee/include/klee/Executor.h EditedS2ESrcFiles/klee-Executor.h > EditedS2ESrcFiles/diff.kleeexecutor.h ${DIFF_END}
	touch $@

${STAMPS_DIR}/mk.publish-s2eexecutor: EditedS2ESrcFiles/s2e-S2EExecutor.cpp EditedS2ESrcFiles/s2e-S2EExecutor.h
	@cp -vu EditedS2ESrcFiles/s2e-S2EExecutor.cpp ${S2E_SRC_DIR}/qemu/s2e/S2EExecutor.cpp
	@cp -vu EditedS2ESrcFiles/s2e-S2EExecutor.h ${S2E_SRC_DIR}/qemu/s2e/S2EExecutor.h
	touch $@

${STAMPS_DIR}/mk.diff-s2eexecutor: EditedS2ESrcFiles/s2e-S2EExecutor.cpp EditedS2ESrcFiles/s2e-S2EExecutor.h
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/qemu/s2e/S2EExecutor.cpp EditedS2ESrcFiles/s2e-S2EExecutor.cpp > EditedS2ESrcFiles/diff.s2eexecutor.cpp ${DIFF_END}
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/qemu/s2e/S2EExecutor.h EditedS2ESrcFiles/s2e-S2EExecutor.h > EditedS2ESrcFiles/diff.s2eexecutor.h ${DIFF_END}
	touch $@

${STAMPS_DIR}/mk.publish-s2eexecstate: EditedS2ESrcFiles/s2e-S2EExecutionState.cpp EditedS2ESrcFiles/s2e-S2EExecutionState.h
	@cp -vu EditedS2ESrcFiles/s2e-S2EExecutionState.cpp ${S2E_SRC_DIR}/qemu/s2e/S2EExecutionState.cpp
	@cp -vu EditedS2ESrcFiles/s2e-S2EExecutionState.h ${S2E_SRC_DIR}/qemu/s2e/S2EExecutionState.h
	touch $@
					 
${STAMPS_DIR}/mk.diff-s2eexecstate: EditedS2ESrcFiles/s2e-S2EExecutionState.cpp EditedS2ESrcFiles/s2e-S2EExecutionState.h
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/qemu/s2e/S2EExecutionState.cpp EditedS2ESrcFiles/s2e-S2EExecutionState.cpp > EditedS2ESrcFiles/diff.s2eexecstate.cpp ${DIFF_END}
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/qemu/s2e/S2EExecutionState.h EditedS2ESrcFiles/s2e-S2EExecutionState.h > EditedS2ESrcFiles/diff.s2eexecstate.h ${DIFF_END}
	touch $@

${STAMPS_DIR}/mk.publish-kleeconstraints: EditedS2ESrcFiles/klee-Constraints.h
	@cp -vu EditedS2ESrcFiles/klee-Constraints.h ${S2E_SRC_DIR}/klee/include/klee/Constraints.h
	touch $@
			 
${STAMPS_DIR}/mk.diff-kleeconstraints: EditedS2ESrcFiles/klee-Constraints.h
	-@${DIFF} ${UNTOUCHED_S2E_SRC_DIR}/klee/include/klee/Constraints.h EditedS2ESrcFiles/klee-Constraints.h > EditedS2ESrcFiles/diff.kleeconstaints.h ${DIFF_END}
	touch $@

${STAMPS_DIR}/mk.publish: ${STAMPS_DIR}/mk.publish-Int ${STAMPS_DIR}/mk.publish-LSys ${STAMPS_DIR}/mk.publish-SysT ${STAMPS_DIR}/mk.publish-CodeXt ${STAMPS_DIR}/mk.publish-mkfiletarget ${STAMPS_DIR}/mk.publish-execall ${STAMPS_DIR}/mk.publish-plugincpp ${STAMPS_DIR}/mk.publish-coreplugin ${STAMPS_DIR}/mk.publish-s2eqemuh ${STAMPS_DIR}/mk.publish-opcodes ${STAMPS_DIR}/mk.publish-traceents ${STAMPS_DIR}/mk.publish-translate ${STAMPS_DIR}/mk.publish-s2eh ${STAMPS_DIR}/mk.publish-kleeexecutor ${STAMPS_DIR}/mk.publish-s2eexecstate ${STAMPS_DIR}/mk.publish-kleeconstraints ${STAMPS_DIR}/mk.publish-kleeexecutor ${STAMPS_DIR}/mk.publish-s2eexecutor
	@echo "Published files"
	touch $@

publish: ${STAMPS_DIR}/mk.publish

${STAMPS_DIR}/mk.diff: ${STAMPS_DIR}/mk.diff-mkfiletarget ${STAMPS_DIR}/mk.diff-execall ${STAMPS_DIR}/mk.diff-plugincpp ${STAMPS_DIR}/mk.diff-coreplugin ${STAMPS_DIR}/mk.diff-s2eqemuh ${STAMPS_DIR}/mk.diff-opcodes ${STAMPS_DIR}/mk.diff-traceents ${STAMPS_DIR}/mk.diff-translate ${STAMPS_DIR}/mk.diff-s2eh ${STAMPS_DIR}/mk.diff-kleeexecutor ${STAMPS_DIR}/mk.diff-s2eexecstate ${STAMPS_DIR}/mk.diff-kleeconstraints ${STAMPS_DIR}/mk.diff-kleeexecutor ${STAMPS_DIR}/mk.diff-s2eexecutor
	@echo "Diff'ed files"
	touch $@

diff: ${STAMPS_DIR}/mk.diff

${STAMPS_DIR}/mk.build-test: ${STAMPS_DIR}/mk.publish
	@echo "First compiling the plugins directory only, to save time if debugging errors"
	${MAKE} -C ${S2E_BUILD_DIR}/qemu-release VERBOSE=1
	touch $@

build-test: ${STAMPS_DIR}/mk.build-test

# consider targeting the actual bniary S2E_QEMU_BIN
${STAMPS_DIR}/mk.build: ${STAMPS_DIR}/mk.publish ${STAMPS_DIR}/mk.build-test
	@echo "Building the S2E version of QEMU"
	${MAKE} -C ${S2E_BUILD_DIR}
	touch $@

build: ${STAMPS_DIR}/mk.build

${STAMPS_DIR}/mk.test: ${STAMPS_DIR}/mk.build
	@echo "Testing S2E with Plugins, but without a HDD. Success if reaches a No bootable device output"
	${S2E_QEMU_BIN} -m 8 -s2e-config-file ${DEVEL_DIR}/CodeXt/${CONF_FILE}
	touch $@

test: ${STAMPS_DIR}/mk.test


${STAMPS_DIR}/mk.run-nons2e: ${STAMPS_DIR}/mk.build
# 	@echo "Running QEMU without S2E, for either sanity check or for a quicker boot (once up run s2eget, save state, and suspend)"
	@echo "Note that S2E can distort qcows after a while, so use the raw disk image every now and again to set things up fresh"
	@echo "Are you sure that you want to do this? Press enter to continue or CTRL+C to exit."
	@read abc
	#${QEMU_BINPATH} -hda ${DISKIMG_DIR}s2e_disk2.raw -redir tcp:2222::22
	${QEMU_BIN} -hda ${DISKIMG_DIR}/${DISKIMG} ${TCP_REDIR}
	touch $@

run-nons2e: ${STAMPS_DIR}/mk.run-nons2e

# called from within shellcode-wrapper make, so no need to have it here
#mk.libdasosf:
#	make -C libDasosf


mk.e-wrapper:
	make -C LoadingBinaries

mk.s-wrapper: #mk.libdasosf
	make -C shellcode-wrapper

mk.stubs:
	make -C stubs

mk.s2ekill:
	make -C s2ekill

mk.s2ecmd:
	make -C s2ecmd

${STAMPS_DIR}/mk.prep-hostfiles: mk.s-wrapper mk.e-wrapper firstRan.sh mk.stubs mk.s2ekill mk.s2ecmd
	@echo "Preparing the HostFiles directory"
	rm ${DEVEL_DIR}/runtime.dir/*
	#@cp -vu stubs/stubs-curr ${DEVEL_DIR}/runtime.dir/.
	@cp -vu s2ekill/s2ekill ${DEVEL_DIR}/runtime.dir/.
	@cp -vu s2ecmd/s2ecmd ${DEVEL_DIR}/runtime.dir/.
	@cp -vu shellcode-wrapper/shellcode-wrapper  ${DEVEL_DIR}/runtime.dir/.
	#@cp -vu shellcode-wrapper/randfilltester-swrapper  ${DEVEL_DIR}/runtime.dir/.
	#@cp -vu ByteArrays/*.dump  ${DEVEL_DIR}/runtime.dir/.
	#@cp -vu ByteArrays/*.rawshell  ${DEVEL_DIR}/runtime.dir/.
	@cp -vu LoadingBinaries/elf-wrapper  ${DEVEL_DIR}/runtime.dir/.
	@cp -vu ByteArrays/*.elf  ${DEVEL_DIR}/runtime.dir/.
	@cp -vu ByteArrays/my.*  ${DEVEL_DIR}/runtime.dir/.
	@cp -vu firstRan.sh  ${DEVEL_DIR}/runtime.dir/.
	mv ${DEVEL_DIR}/HostFiles/pkg.tar ${DEVEL_DIR}/HostFiles/pkg.tar.old
	tar cvf ${DEVEL_DIR}/HostFiles/pkg.tar runtime.dir/*
	touch $@

# QEMU requires a properly windowed environment, so you can not run it over SSH X sessions: if you do, then you will receive an error about SDL.
${STAMPS_DIR}/mk.run: ${STAMPS_DIR}/mk.build ${STAMPS_DIR}/mk.prep-hostfiles 
	@echo "Resuming the VM (waiting with s2eget) for a test"
	${S2E_QEMU_BIN} -s2e-config-file ${DEVEL_DIR}/CodeXt/${CONF_FILE} -hda ${DISKIMG_DIR}/${DISKIMG} ${TCP_REDIR} -loadvm ${SAVED_STATE}
	#${S2E_QEMU_BIN} -s2e-config-file ${DEVEL_DIR}/stubs/conf-stubs.lua -hda ${DISKIMG_DIR}/${DISKIMG} -redir tcp:2222::22 -loadvm ${SAVED_STATE}
	touch $@
	@echo "To see the output of the plugin run: tail -f s2e-last/debug.txt"

# if you don't delete the stamp, then make will claim there is nothing to do for run
del-mk.run:
	@rm -f ${STAMPS_DIR}/mk.run

run: del-mk.run ${STAMPS_DIR}/mk.run

# It is possible to attach GDB to any running instance of S2E. S2E relies on the QEMU's GDB interface, which can be enabled with the -s command line option. This option creates a socket on the port number 1234.
# $ gdb /path/to/my/prog (gdb) target remote localhost:1234 #use gdb as usual (set breakpoints, source directories, single-step, etc.).
${STAMPS_DIR}/mk.debug: ${STAMPS_DIR}/mk.build ${STAMPS_DIR}/mk.prep-hostfiles 
	@echo "Resuming the VM (waiting with s2eget) for a test in debug mode"
	${S2E_QEMU_BIN} -s2e-config-file ${DEVEL_DIR}/CodeXt/${CONF_FILE} -hda ${DISKIMG_DIR}/${DISKIMG} ${TCP_REDIR} -loadvm ${SAVED_STATE} -s
	touch $@
	@echo "To see the output of the plugin run: tail -f s2e-last/debug.txt"

del-mk.debug:
	@rm -f ${STAMPS_DIR}/mk.debug

debug: del-mk.debug ${STAMPS_DIR}/mk.debug

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

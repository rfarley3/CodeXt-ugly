/*
 * SyscallMonitor.h
 *
 *  Created on: Dec 8, 2011
 *      Author: zaddach
 */

#ifndef SYSCALLMONITOR_H_
#define SYSCALLMONITOR_H_

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/InterruptMonitor.h>

#include <vector>
#include <map>

namespace s2e {
namespace plugins {



/**
 * This plugin monitors the system for Linux syscalls (Kernel entry points in userspace) and emits a signal
 * once a syscall is executed. The user can then use another signal that is passed during the syscall entry
 * point to register also for the syscall exit point.
 *
 * Syscalls on the linux platform can be executed in three ways:
 *  <ul>
 *    <li>The traditional method is to issue a software interrupt with the number 0x80. The syscall number is
 *        placed in register EAX. For system calls with less than 7 parameters, these are placed in EBX, ECX, EDX,
 *        ESI, EDI, EBP. For system calls with more parameters, EBX will contain a pointer to a memory structure
 *        with the parameters.</li>
 *    <li>The SYSENTER instruction is a new syscall entry method introduced by Intel. The context switch is faster
 *        than with an interrupt, and syscall number and parameters are passed with the same convention as for
 *        the interrupt.</li>
 *    <li>The SYSCALL instruction was introducted by AMD for 64 bit processors. As such it will not occur in
 *        the 32 bit code executed by S2E and is not handled.</li>
 *  </ul>
 *
 *  The end of a syscall is detected by monitoring for the corresponding IRET (for INT entry) or SYSEXIT (for SYSENTER entry)
 *  instruction.
 */
class LinuxSyscallMonitor : public Plugin
{
	S2E_PLUGIN
public:
	static const int MAX_SYSCALL_NR = 444;
	enum ESyscallType {SYSCALL_INT, SYSCALL_SYSENTER, SYSCALL_SYSCALL};
	struct SSyscallInformation
	{
		int argumentCount;
		int flags;
		const char * name;
		int misc;
	};

	typedef enum ESyscallType SyscallType;
	typedef struct SSyscallInformation SyscallInformation;
	typedef sigc::signal<void, S2EExecutionState*, uint64_t> SyscallReturnSignal;
	typedef sigc::signal<void, S2EExecutionState*, uint64_t, SyscallType, uint32_t, SyscallReturnSignal& > SyscallSignal;
	typedef std::map< uint32_t, std::vector< LinuxSyscallMonitor::SyscallReturnSignal > > SyscallReturnSignalsMap;

	LinuxSyscallMonitor(S2E*);
	virtual ~LinuxSyscallMonitor();

	void initialize();
	void onTranslateBlockEnd(ExecutionSignal *signal,
	                                          S2EExecutionState *state,
	                                          TranslationBlock *tb,
	                                          uint64_t pc, bool, uint64_t);
	void onSysenter(S2EExecutionState* state, uint64_t pc);
	void onSysexit(S2EExecutionState* state, uint64_t pc);
	void onInt80(S2EExecutionState* state, uint64_t pc, int int_num, InterruptMonitor::InterruptReturnSignal& signal);
	static const SyscallInformation& getSyscallInformation(int syscallNr);
	SyscallSignal& getSyscallSignal(S2EExecutionState* state, int syscallNr);
	SyscallSignal& getAllSyscallsSignal(S2EExecutionState* state);
protected:
	void emitSyscallSignal(S2EExecutionState* state, uint64_t pc, SyscallType syscall_type, SyscallReturnSignal& signal);
private:
	static SyscallInformation m_syscallInformation[];
	bool m_initialized;

};

class LinuxSyscallMonitorState : public PluginState
{
private:
	LinuxSyscallMonitor::SyscallSignal m_allSyscallsSignal;
	std::map<int, LinuxSyscallMonitor::SyscallSignal> m_signals;
	LinuxSyscallMonitor::SyscallReturnSignalsMap m_returnSignals;
	LinuxSyscallMonitor* m_plugin;
public:
	virtual LinuxSyscallMonitorState* clone() const;
	static PluginState *factory(Plugin *p, S2EExecutionState *s);

	friend class LinuxSyscallMonitor;
};


} //namespace plugins
} //namespace s2e

#endif /* SYSCALLMONITOR_H_ */

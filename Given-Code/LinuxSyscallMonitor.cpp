/*
 * LinuxSyscallMonitor.cpp
 *
 *  Created on: Dec 8, 2011
 *      Author: zaddach
 */

extern "C" {
#include <qemu-common.h>
}

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/LinuxSyscallMonitor.h>
#include <s2e/Plugins/InterruptMonitor.h>
#include <s2e/Utils.h> // hexval


namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LinuxSyscallMonitor, "Linux syscall monitoring plugin", "",);

static const int TP = 0x1;
static const int TD = 0x2;
static const int TF = 0x4;
static const int NF = 0x8;
static const int TN = 0x10;
static const int TI = 0x20;
static const int TS = 0x40;

LinuxSyscallMonitor::SyscallInformation LinuxSyscallMonitor::m_syscallInformation[] = {
#include "syscallent-simple.h"
};

LinuxSyscallMonitor::LinuxSyscallMonitor(S2E* s2e) : Plugin(s2e) {
	// TODO Auto-generated constructor stub

}

LinuxSyscallMonitor::~LinuxSyscallMonitor() {
	// TODO Auto-generated destructor stub
}

void LinuxSyscallMonitor::initialize()
{
	s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &LinuxSyscallMonitor::onTranslateBlockEnd));
//	s2e()->getCorePlugin()->onTranslateJumpStart.connect(sigc::mem_fun(*this, &LinuxSyscallMonitor::onTranslateJumpStart));

	m_initialized = false;
}

void LinuxSyscallMonitor::onTranslateBlockEnd(ExecutionSignal *signal,
                                          S2EExecutionState *state,
                                          TranslationBlock *tb,
                                          uint64_t pc, bool, uint64_t)
{
	if (!m_initialized)
	{
		Plugin* intMonPlugin = s2e()->getPlugin("InterruptMonitor");

		if (intMonPlugin)
		{
			reinterpret_cast<InterruptMonitor *>(intMonPlugin)->getInterruptSignal(state, 0x80).connect(sigc::mem_fun(*this, &LinuxSyscallMonitor::onInt80));
		}
		else
		{
			s2e()->getWarningsStream() << "InterruptMonitor plugin missing. Cannot monitor syscalls via int 0x80" << "\n"; //std::endl;
		}

		m_initialized = true;
	}

	if (tb->s2e_tb_type == TB_SYSENTER)
	{
		signal->connect(sigc::mem_fun(*this, &LinuxSyscallMonitor::onSysenter));
	}
	else if (tb->s2e_tb_type == TB_SYSEXIT)
	{
		signal->connect(sigc::mem_fun(*this, &LinuxSyscallMonitor::onSysexit));
	}
}

void LinuxSyscallMonitor::onSysenter(S2EExecutionState* state, uint64_t pc)
{
	target_ulong ebp = 0;
	target_ulong eip = 0;

	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);

	//On SYSENTER, the current stack pointer of the user mode code is stored in EBP, exactly the SYSENTER is
	//preceded by
	//xxxxxxxx: call 0xffffe400
	//ffffe400: 51 push %ecx
	//ffffe401: 52 push %edx
	//ffffe402: 55 push %ebp
	//ffffe403: 89 e5 mov %esp,%ebp
	//ffffe405: 0f 34 sysenter
	//(from linux-gate.so)
	//HAHA, the above information is correct, but I got fooled by the assumption that SYSEXIT directly
	//jumps to the return point - it does not, but jumps instead after the SYSCALL instruction in the
	//vsyscall page. So to summarize, there is only ONE SYSCALL instruction, which is located in the vsyscall
	//page at 0xffff4000, and SYSEXIT always returns to after this instruction.
	if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBP]), &ebp, sizeof(ebp)))
	{
		s2e()->getWarningsStream() << "SYSENTER has symbolic EBP value at 0x" << hexval(pc) << "\n"; //std::endl;
	}

	if (!state->readMemoryConcrete(ebp + 12, &eip, sizeof(eip), S2EExecutionState::VirtualAddress))
	{
		s2e()->getWarningsStream() << "SYSENTER has symbolic EIP value at 0x" << hexval(pc) << "\n"; //std::endl;
	}


	plgState->m_returnSignals[eip].push_back(SyscallReturnSignal());


//	s2e()->getDebugStream() << "SYSENTER return address 0x" << hexval(eip) << "\n"; //std::endl;
	emitSyscallSignal(state, pc, SYSCALL_SYSENTER, plgState->m_returnSignals[eip].back());
}

void LinuxSyscallMonitor::onSysexit(S2EExecutionState* state, uint64_t pc)
{
	target_ulong esp = 0;
	target_ulong eip = 0;

	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);

	if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]), &esp, sizeof(esp)))
	{
		s2e()->getWarningsStream() << "SYSEXIT has symbolic EBP at 0x" << hexval(pc) << "\n"; //std::endl;
	}

	if (!state->readMemoryConcrete(esp + 12, &eip, sizeof(eip), S2EExecutionState::VirtualAddress))
	{
		s2e()->getWarningsStream() << "SYSEXIT has symbolic return address at 0x" << hexval(pc) << "\n"; //std::endl;
	}

	SyscallReturnSignalsMap::iterator itr = plgState->m_returnSignals.find(eip);

	if (itr != plgState->m_returnSignals.end())
	{
		SyscallReturnSignal& sig = itr->second.back();
		sig.emit(state, pc);
		itr->second.pop_back();
	}


//	s2e()->getDebugStream() << "SYSEXIT at 0x" << hexval(pc) << " returning to 0x" << hexval(eip) << "\n"; //std::endl;
}

void LinuxSyscallMonitor::onInt80(S2EExecutionState* state, uint64_t pc, int int_num, InterruptMonitor::InterruptReturnSignal& signal)
{
	if (int_num == 0x80)
	{
		emitSyscallSignal(state, pc, SYSCALL_INT, signal);
	}
	else
	{
		s2e()->getDebugStream() << "LinuxSyscallMonitor received interrupt signal from InterruptMonitor that was not int 0x80" << "\n"; //std::endl;
	}
}

const LinuxSyscallMonitor::SyscallInformation& LinuxSyscallMonitor::getSyscallInformation(int syscallNr) {
	static SyscallInformation symbolic_syscall = {0, 0, "symbolic syscall number", 0};

	assert(syscallNr >= -1 && syscallNr <= MAX_SYSCALL_NR);

	if (syscallNr == -1)
	{
		return symbolic_syscall;
	}

	return m_syscallInformation[syscallNr];
}

LinuxSyscallMonitor::SyscallSignal& LinuxSyscallMonitor::getAllSyscallsSignal(S2EExecutionState* state)
{
	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);

	return plgState->m_allSyscallsSignal;
}

LinuxSyscallMonitor::SyscallSignal& LinuxSyscallMonitor::getSyscallSignal(S2EExecutionState* state, int syscallNr)
{
	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);

	assert(syscallNr >= 0 && syscallNr < MAX_SYSCALL_NR);

	return plgState->m_signals[syscallNr];
}

void LinuxSyscallMonitor::emitSyscallSignal(S2EExecutionState* state, uint64_t pc, SyscallType syscall_type, SyscallReturnSignal& signal)
{
	uint32_t eax = 0xFFFFFFFF;
	//target_ulong cr3 = state->readCpuState(CPU_OFFSET(cr[3]), sizeof(target_ulong) * 8);

	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);

	if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &eax, sizeof(eax)))
	{
		s2e()->getWarningsStream() << "Syscall with symbolic syscall number (EAX)!" << "\n"; //std::endl;
	}

	if (eax != 0xFFFFFFFF)
	{
		std::map<int, SyscallSignal>::iterator itr = plgState->m_signals.find(eax);

		if (itr != plgState->m_signals.end())
		{
			itr->second.emit(state, pc, syscall_type, eax, signal);
		}
	}

	plgState->m_allSyscallsSignal.emit(state, pc, syscall_type, eax, signal);

//	s2e()->getDebugStream() << "0x" << hexval(pc) << ": System call 0x" << hexval(eax) << "/" <<
//			getSyscallInformation(eax).name << " (" << syscall_type << ") in process " << hexval(cr3) << "\n"; //std::endl;
}


LinuxSyscallMonitorState* LinuxSyscallMonitorState::clone() const
{
	LinuxSyscallMonitorState *ret = new LinuxSyscallMonitorState(*this);
//    m_plugin->s2e()->getDebugStream() << "Forking FunctionMonitorState ret=" << hexval(ret) << "\n"; //std::endl;
    assert(ret->m_returnSignals.size() == m_returnSignals.size());
    return ret;
}

PluginState *LinuxSyscallMonitorState::factory(Plugin *p, S2EExecutionState *s)
{
	LinuxSyscallMonitorState *ret = new LinuxSyscallMonitorState();
    ret->m_plugin = static_cast<LinuxSyscallMonitor*>(p);
    return ret;
}




} //namespace plugins
} //namespace s2e


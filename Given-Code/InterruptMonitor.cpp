/*
 * InterruptMonitor.cpp
 *
 *  Created on: Dec 8, 2011
 *      Author: zaddach
 */

extern "C" {
#include <qemu-common.h>
}

#include <vector>
#include <map>

#include <s2e/S2E.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/InterruptMonitor.h>
#include <s2e/Utils.h> // hexval


using std::vector;
using std::map;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(InterruptMonitor, "software interrupt monitoring plugin", "",);

InterruptMonitor::InterruptMonitor(S2E* s2e) : Plugin(s2e)
{
	// TODO Auto-generated constructor stub

}

InterruptMonitor::~InterruptMonitor() {
	// TODO Auto-generated destructor stub
}

void InterruptMonitor::initialize()
{
	s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &InterruptMonitor::slotTranslateBlockEnd));
	s2e()->getCorePlugin()->onTranslateJumpStart.connect(sigc::mem_fun(*this, &InterruptMonitor::onTranslateJumpStart));
}

InterruptMonitor::InterruptSignal& InterruptMonitor::getInterruptSignal(S2EExecutionState* state, int interrupt)
{
	DECLARE_PLUGINSTATE(InterruptMonitorState, state);

	assert (interrupt >= -1 && interrupt <= 0xff);

	return plgState->m_signals[interrupt];
}

void InterruptMonitor::slotTranslateBlockEnd(ExecutionSignal *signal,
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc, bool, uint64_t)
{

	if (tb->s2e_tb_type == TB_INTERRUPT)
	{
		signal->connect(sigc::mem_fun(*this, &InterruptMonitor::onInterrupt));
	}
}

void InterruptMonitor::onTranslateJumpStart(ExecutionSignal *signal,
                                             S2EExecutionState *state,
                                             TranslationBlock * tb,
                                             uint64_t pc, int jump_type)
{
	if (jump_type == JT_IRET)
	{
		signal->connect(sigc::mem_fun(*this, &InterruptMonitor::onInterruptReturn));
	}
}

void InterruptMonitor::onInterruptReturn(S2EExecutionState* state, uint64_t pc)
{
	target_ulong esp = 0;
	target_ulong eip = 0;

	DECLARE_PLUGINSTATE(InterruptMonitorState, state);

	if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ESP]), &esp, sizeof(esp)))
	{
		s2e()->getWarningsStream() << "IRET has symbolic ESP register at 0x" << hexval(pc) << "\n"; //std::endl;
	}

	if (!state->readMemoryConcrete(esp, &eip, sizeof(eip), S2EExecutionState::VirtualAddress))
	{
		s2e()->getWarningsStream() << "IRET at 0x" << hexval(pc) << " has symbolic EIP value at memory address 0x" <<
				hexval(esp) << "\n"; //std::endl;
	}


	ReturnSignalsMap::iterator itr = plgState->m_returnSignals.find(eip);

	if (itr != plgState->m_returnSignals.end())
	{
		if (itr->second.empty())
		{
			s2e()->getWarningsStream() << "Vector of signals was empty when trying to find interrupt for IRET to 0x" <<
					hexval(eip) << "\n"; //std::endl;
		}
		else
		{
			InterruptReturnSignal returnSignal = itr->second.back();
//D			s2e()->getDebugStream() << "Received IRET for INT at 0x" << hexval(itr->first) << "\n"; //std::endl;
			returnSignal.emit(state, pc);
			itr->second.pop_back();
		}

	}
	else
	{
//D		s2e()->getDebugStream() << "no return signal for IRET at 0x" << hexval(eip) << " found" << "\n"; //std::endl;
	}

//D	s2e()->getDebugStream() << "IRET at 0x" << hexval(pc) << " returning to " << hexval(eip) << "\n"; //std::endl;
}

void InterruptMonitor::onInterrupt(S2EExecutionState* state, uint64_t pc)
{
	char insnByte;
	int intNum = -1;

	DECLARE_PLUGINSTATE(InterruptMonitorState, state);

	if (!state->readMemoryConcrete(pc, &insnByte, 1))
	{
		s2e()->getWarningsStream() << "Could not read interrupt instruction at 0x" << hexval(pc) << "\n"; //std::endl;
		return;
	}

	if ((insnByte & 0xFF) == 0xCC)
	{
		intNum = 3;
	}
	else if ((insnByte & 0xFF) == 0xCD)
	{
		unsigned char intNumByte;

		if (!state->readMemoryConcrete(pc + 1, &intNumByte, 1))
		{
			s2e()->getWarningsStream() << "Could not read interrupt index at 0x" << hexval(pc) << "\n"; //std::endl;
			return;
		}

		intNum = (int) intNumByte;
	}
	else
	{
		/* Invalid Opcode */
		s2e()->getWarningsStream() << "Unexpected opcode 0x" << hexval((unsigned int) insnByte) << " at 0x" <<
				hexval(pc) << ", expected 0xcc or 0xcd\n"; //std::endl;
		return;
	}

	assert(intNum != -1);

	//Generate a signal that will be called once the interrupt returns
	//TODO: make object handling of signals more efficient

	plgState->m_returnSignals[pc + 2].push_back(InterruptReturnSignal());
	InterruptReturnSignal& returnSignal = plgState->m_returnSignals[pc + 2].back();

	//Find and notify signals for this interrupt no
	std::map<int, InterruptSignal>::iterator itr = plgState->m_signals.find(intNum);

	if (itr != plgState->m_signals.end())
	{
		itr->second.emit(state, pc, intNum, returnSignal);
	}

	//Always notify signal at -1
	plgState->m_signals[-1].emit(state, pc, intNum, returnSignal);

//D	s2e()->getDebugStream() << "Received interrupt 0x" << hexval(intNum) << " at 0x" << hexval(pc) << "\n"; //std::endl;
}

InterruptMonitorState* InterruptMonitorState::clone() const
{
    InterruptMonitorState *ret = new InterruptMonitorState(*this);
//    m_plugin->s2e()->getDebugStream() << "Forking FunctionMonitorState ret=" << hexval(ret) << "\n"; //std::endl;
    assert(ret->m_returnSignals.size() == m_returnSignals.size());
    return ret;
}

PluginState *InterruptMonitorState::factory(Plugin *p, S2EExecutionState *s)
{
	InterruptMonitorState *ret = new InterruptMonitorState();
    ret->m_plugin = static_cast<InterruptMonitor*>(p);
    return ret;
}




} //namespace plugins
} //namespace s2e


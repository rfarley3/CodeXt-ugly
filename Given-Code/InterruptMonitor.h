/*
 * InterruptMonitor.h
 *
 *  Created on: Dec 8, 2011
 *      Author: zaddach
 */

#ifndef INTERRUPTMONITOR_H_
#define INTERRUPTMONITOR_H_

#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

// RJF
#include <s2e/Plugins/ModuleDescriptor.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/OSMonitor.h>
// end RJF 

#include <map>
#include <vector>

namespace s2e {
namespace plugins {

class InterruptMonitor : public Plugin
{
	S2E_PLUGIN

public:
	typedef sigc::signal< void, S2EExecutionState*, uint64_t > InterruptReturnSignal;
	typedef sigc::signal< void, S2EExecutionState*, uint64_t, int, InterruptReturnSignal& > InterruptSignal;
	typedef std::map< uint32_t, std::vector< InterruptReturnSignal > > ReturnSignalsMap;


	InterruptMonitor(S2E* s2e);
	virtual ~InterruptMonitor();

	void initialize();

	InterruptSignal& getInterruptSignal(S2EExecutionState* state, int interrupt);
	void slotTranslateBlockEnd(ExecutionSignal*, S2EExecutionState *state,
	                               TranslationBlock *tb, uint64_t pc,
	                               bool, uint64_t);
	void onTranslateJumpStart(ExecutionSignal *signal,
	                                             S2EExecutionState *state,
	                                             TranslationBlock * tb,
	                                             uint64_t pc, int jump_type);
	void onInterruptReturn(S2EExecutionState* state, uint64_t pc);
	void onInterrupt(S2EExecutionState*, uint64_t);
private:
//	bool m_initialized;

};

class InterruptMonitorState : public PluginState
{
private:
	std::map<int, InterruptMonitor::InterruptSignal> m_signals;
	InterruptMonitor::ReturnSignalsMap m_returnSignals;
	InterruptMonitor* m_plugin;
public:
	virtual InterruptMonitorState* clone() const;
	static PluginState *factory(Plugin *p, S2EExecutionState *s);

	friend class InterruptMonitor;
};

} //namespace plugins
} //namespace s2e

#endif /* INTERRUPTMONITOR_H_ */

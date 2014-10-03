#ifndef S2E_PLUGINS_SYSCALLTRACKER_H
#define S2E_PLUGINS_SYSCALLTRACKER_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/LinuxSyscallMonitor.h>
#include "offset_defines.h"

namespace s2e {
namespace plugins {

class SyscallTracker : public Plugin
{
    S2E_PLUGIN
public:
    SyscallTracker(S2E* s2e): Plugin(s2e) {}


    void initialize();
    
    void onException(s2e::S2EExecutionState*, unsigned int, uint64_t);
    
    void onTranslateBlockEnd(ExecutionSignal, S2EExecutionState, TranslationBlock, uint64_t, bool, uint64_t);
    void onSysexit(S2EExecutionState* , uint64_t);
    void onSysenter(S2EExecutionState* , uint64_t);
    
    void onSyscall(S2EExecutionState*, uint64_t, LinuxSyscallMonitor::SyscallType, uint32_t, LinuxSyscallMonitor::SyscallReturnSignal& );
    void onFirstInstruction( ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc);
private:
    sigc::connection * firstInstructionConnection;
};

class SyscallTrackerState: public PluginState
{

public:
    SyscallTrackerState() {
 
    }

    ~SyscallTrackerState() {}

    static PluginState *factory(Plugin*, S2EExecutionState*) {
        return new SyscallTrackerState();
    }

    SyscallTrackerState *clone() const {
        return new SyscallTrackerState(*this);
    }


};

} // namespace plugins
} // namespace s2e

#endif
    

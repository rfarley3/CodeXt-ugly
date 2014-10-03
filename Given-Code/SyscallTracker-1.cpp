#include <s2e/S2E.h>
#include "SyscallTracker.h"
#include <s2e/S2EExecutionState.h>

extern struct CPUX86State *env;
extern s2e::S2EExecutionState *state;

namespace s2e {
namespace plugins {

//Define a plugin whose class is SyscallTracker and called "SyscallTracker".
//The plugin does not have any dependency.
S2E_DEFINE_PLUGIN(SyscallTracker, "Tracking Syscalls", "LinuxSyscallMonitor",);

void SyscallTracker::initialize()
{
	//extern s2e::S2EExecutionState *state;
	//DECLARE_PLUGINSTATE(SyscallTrackerState, state);

	LinuxSyscallMonitor *monitor= static_cast<LinuxSyscallMonitor*>(s2e()->getPlugin("LinuxSyscallMonitor"));
	    assert(monitor);
//s2e::S2EExecutionState *state = new S2EExecutionstate;  
	monitor -> getAllSyscallsSignal(state).connect(sigc::mem_fun(*this,&SyscallTracker::onSyscall));
	
	//static_cast<LinuxSyscallMonitor*>(s2e()->getPlugin("LinuxSyscallMonitor"))->LinuxSyscallMonitor::SyscallSignal.connect(sigc::mem_fun(*this, &SyscallTracker::onSyscall));
	//m_executionDetector = (ModuleExecutionDetector*)s2e()->getPlugin("ModuleExecutionDetector");
	
	//s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &SyscallTracker::onTranslateBlockEnd));

}

void SyscallTracker::onSyscall( S2EExecutionState* state, uint64_t pc, LinuxSyscallMonitor::SyscallType sysc_type, uint32_t sysc_number, LinuxSyscallMonitor::SyscallReturnSignal& returnsignal)
{
	std::ostream& stream = 	s2e()->getDebugStream();
	stream << "Syscall number " << std::hex << sysc_number << std::endl;
}


} // namespace plugins
} // namespace s2e



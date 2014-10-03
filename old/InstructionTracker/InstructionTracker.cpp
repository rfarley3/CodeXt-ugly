#ifndef S2E_PLUGINS_INSTRTRACKER_CPP
#define S2E_PLUGINS_INSTRTRACKER_CPP

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>      // needed to read conf files
#include "InstructionTracker.h"

//#include <iostream> 
//using namespace std;

namespace s2e {
namespace plugins {

//Define a plugin whose class is InstructionTracker and called "InstructionTracker".
//The plugin does not have any dependency.
S2E_DEFINE_PLUGIN(InstructionTracker, "Tutorial - Tracking instructions", "InstructionTracker",);

void InstructionTracker::initialize()
{
   m_address = s2e()->getConfig()->getInt(getConfigKey() + ".addressToTrack");
   
   //This indicates that our plugin is interested in monitoring instruction translation.
   //For this, the plugin registers a callback with the onTranslateInstruction signal.
   s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
      sigc::mem_fun(*this, &InstructionTracker::onTranslateInstruction));
}

void InstructionTracker::onTranslateInstruction(ExecutionSignal *signal,
                                                S2EExecutionState *state,
                                                TranslationBlock *tb,
                                                uint64_t pc)
{
   if(m_address == pc) {
      //When we find an interesting address, ask S2E to invoke our
      //callback when the address is actually executed.
      signal->connect(sigc::mem_fun(*this, &InstructionTracker::onInstructionExecution));
   }
}

//This callback is called only when the instruction at our address is executed.
//The callback incurs zero overhead for all other instructions.
void InstructionTracker::onInstructionExecution(S2EExecutionState *state, uint64_t pc)
{
   s2e()->getDebugStream() << "Executing instruction at " << pc << "\n"; //std::endl;
   //The plugins can arbitrarily modify/observe the current execution state via
   //the execution state pointer.
   //Plugins can also call the s2e() method to use the S2E API.
}

} // namespace plugins
} // namespace s2e

#endif




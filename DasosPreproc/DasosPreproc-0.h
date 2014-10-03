#ifndef S2E_PLUGINS_DASOS_PREPROC_H
#define S2E_PLUGINS_DASOS_PREPROC_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/LinuxSyscallMonitor.h>
#include "ExecutionTracers/ExecutionTracer.h"
#include <vector>
//#include <s2e/Plugins/OSMonitor.h>
//RJF
//#include "offset_defines.h"
//static const struct sysent sysent0[] = {
//   #include "syscallent-simple.h"
//};

// end RJF

namespace s2e {
namespace plugins {

class DasosPreproc : public Plugin { //public OSMonitor { //
   S2E_PLUGIN

private:
   ExecutionTracer *m_executionTracer;
   sigc::connection m_tiConnection;
   //sigc::connection * firstInstructionConnection;
   sigc::connection * customInstructionConnection;
   
public:
   
   struct Cfg_ {
      bool is_loaded;
      uint64_t base_addr;
      uint64_t byte_len;
      uint64_t end_addr;  // yea I know it's redundant (base_addr+byte_len), but it's handy
      uint64_t eip_addr;
      uint64_t proc_id;
      uint64_t sysc;
    } cfg;
    
   // it may be necessary to use uint64_ts so importing from registers doesn't overwrite anything in the struct out of bounds (like the other members)
   /*struct Fuzz_Cfg_ {
      //s2e::S2EExecutionState* orig_state;
      //s2e::S2EExecutionState* curr_state;
      //s2e::S2EExecutionState* next_state;
      //s2e::S2EExecutionState** states;
      //bool is_fuzzing;
      //uint64_t* ptr;
      //uint64_t ptr_addr;
      uint64_t start;
      uint64_t end;
      //uint64_t orig_val;
      //uint64_t pos;
   } fuzz_cfg;*/
   
   DasosPreproc (S2E* s2e): Plugin (s2e) {}

   ~DasosPreproc () {
   }

   void initialize ();
    
    
   //void onTranslateBlockEnd (ExecutionSignal, S2EExecutionState, TranslationBlock, uint64_t, bool, uint64_t);
   //void onException (s2e::S2EExecutionState*, unsigned int, uint64_t);
   //void onSysexit (S2EExecutionState* , uint64_t);
   //void onSysenter (S2EExecutionState* , uint64_t);
   
   bool isInShell (uint64_t pc);
   void onSyscall (S2EExecutionState*, uint64_t, LinuxSyscallMonitor::SyscallType, uint32_t, LinuxSyscallMonitor::SyscallReturnSignal& );
   
   //void onFirstInstruction (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc);
   void onCustomInstruction (S2EExecutionState* state, uint64_t opcode);
   void activateModule (S2EExecutionState* state);
   void onTranslateInstructionStart (ExecutionSignal *signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc);
   void onTraceInstruction (S2EExecutionState* state, uint64_t pc);

   void fuzzFork (S2EExecutionState* state);
   void fuzzFork1 (S2EExecutionState* state, unsigned int value);
};



class DasosPreprocState: public PluginState {
private:
   uint64_t iCount;
   std::vector<uint64_t> pcs;
   
public:
   DasosPreprocState ();
   DasosPreprocState (S2EExecutionState *s, Plugin *p);
   virtual ~DasosPreprocState ();
   virtual PluginState *clone () const;
   static PluginState *factory (Plugin* p, S2EExecutionState* s);
   
   friend class DasosPreproc;
};

} // namespace plugins
} // namespace s2e

#endif
    

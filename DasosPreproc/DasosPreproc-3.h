#ifndef S2E_PLUGINS_DASOS_PREPROC_H
#define S2E_PLUGINS_DASOS_PREPROC_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/LinuxSyscallMonitor.h>
#include "ExecutionTracers/ExecutionTracer.h"
#include <vector>


#define MAX_SYSCALL_NUM 512


namespace s2e {
namespace plugins {

class DasosPreproc : public Plugin { 
   S2E_PLUGIN

private:
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
      std::vector< std::vector<uint64_t> > successes;
    } cfg;
   
   DasosPreproc (S2E* s2e): Plugin (s2e) {}

   ~DasosPreproc () {
   }

   void initialize ();
   
   bool isInShell (uint64_t pc);
   bool isPathSubset (std::vector<uint64_t> needle, std::vector<uint64_t> haystack);
   bool isPathUnique (std::vector<uint64_t> path);
   void onSyscall (S2EExecutionState*, uint64_t, LinuxSyscallMonitor::SyscallType, uint32_t, LinuxSyscallMonitor::SyscallReturnSignal& );
   
   void onCustomInstruction (S2EExecutionState* state, uint64_t opcode);
   void activateModule (S2EExecutionState* state);
   void onTranslateInstructionStart (ExecutionSignal *signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc);
   void onTraceInstruction (S2EExecutionState* state, uint64_t pc);

   void fuzzFork (S2EExecutionState* state, unsigned int start, unsigned int end);
   void fuzzFork1 (S2EExecutionState* state, unsigned int value);
};



class DasosPreprocState: public PluginState {
private:
   uint64_t iCount;
   std::vector<uint64_t> pcs;
   //ExecutionTracer *m_executionTracer;
   sigc::connection onTransInsnConnection;
   //sigc::connection onTraceInsnConnection;
   //bool onTraceInsnConnected;
   
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
    

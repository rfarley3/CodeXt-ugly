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
   bool isPathDiff (std::vector<uint64_t> p1, std::vector<uint64_t> p2);
   bool isPathSubset (std::vector<uint64_t> needle, std::vector<uint64_t> haystack);
   bool isPathUnique (std::vector<uint64_t> path);
   void onSyscall (S2EExecutionState*, uint64_t, LinuxSyscallMonitor::SyscallType, uint32_t, LinuxSyscallMonitor::SyscallReturnSignal& );
   
   void onCustomInstruction (S2EExecutionState* state, uint64_t opcode);
   void activateModule (S2EExecutionState* state);
   void onTranslateInstructionStart (ExecutionSignal *signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc);
   void onTranslateInstructionEnd (ExecutionSignal *signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc);
   //void onTraceInstruction (S2EExecutionState* state, uint64_t pc);
   //void addPcInstance (uint64_t pc, uint64_t base, S2EExecutionState* state, TranslationBlock *tb);
   
   void printMemMap (S2EExecutionState* state, uint64_t base, unsigned len);
   
   void fuzzFork (S2EExecutionState* state, unsigned int start, unsigned int end);
   void fuzzFork1 (S2EExecutionState* state, unsigned int value);
};



class DasosPreprocState: public PluginState {
private:
   //uint64_t iCount;
   //std::vector<uint64_t> pcs;
   // an array of captured instructions' values (these values are 1-15B long)
   //std::vector</*each element index is PC-base and represents a unique PC*/ std::vector</*each time the PC was called*/ std::vector</*byte values of the insn for that call*/uint8_t> > > mem_map; 
   //sigc::connection oTICS_connection;
   //bool oTICS_connected;
   sigc::connection oTICE_connection;
   bool oTICE_connected;
   
   // keep track of insns executed
   // make an array of insns that become a trace
   // start by defining an insn, leverage memory snapshots to avoid duplicating data
   struct insn {
      uint32_t snapshot_idx; // which snapshot
      uint64_t pc; // offset/pc of insn
      uint16_t len; // num bytes of insn
      //Store insn byte string... Maybe? Or llvm ir decoding? Or disasm?
   };
   
   // as insn are executed, add them to mem map snapshot stack,
   //and then note which stack index as well as the pc and byte len within index
   std::vector<struct insn> trace;
   
   
   // keep track of memory bytes executed as a memory map
   // but they can change, so anytime a previously execed byte changes,
   make a new empty snapshot and start filling it in
   // so make a stack of snapshots
   // start by making
   struct mem_byte {
      uint8_t byte; // value of this byte
      unsigned times_execed; // times this byte was executed (eg loop)
   };
   
   // make an array of mem_bytes the length of the input buffer
   typedef std::vector<struct mem_byte> snapshot;
   
   // make a stack of snapshot
   std::vector<snapshot> mem_map;
   
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
    

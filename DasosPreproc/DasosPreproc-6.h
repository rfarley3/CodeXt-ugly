#ifndef S2E_PLUGINS_DASOS_PREPROC_H
#define S2E_PLUGINS_DASOS_PREPROC_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/LinuxSyscallMonitor.h>
#include "ExecutionTracers/ExecutionTracer.h"
#include <vector>

#include <iostream>
#include <iomanip>

#include <udis86.h>


#define MAX_SYSCALL_NUM 512
#ifndef UNKNOWNS
#define SYSC_UNKNOWN 1024
#define EIP_UNKNOWN 0
#define UNKNOWNS
#endif

// keep track of insns executed
// make an array of insns that become a trace
// start by defining an insn, leverage memory snapshots to avoid duplicating data
struct insn_instance {
   uint32_t snapshot_idx;  // which snapshot
   uint64_t pc;            // offset/pc of insn NOTE: within the snapshot (ie pc - cfg.base_addr)
   uint16_t len;           // num bytes of insn
   //Store insn byte string... Maybe? Or llvm ir decoding? Or disasm?
};

// as insn are executed, add them to mem map snapshot stack,
//and then note which stack index as well as the pc and byte len within index
typedef std::vector<struct insn_instance> Trace;

// keep track of memory bytes executed as a memory map
// but they can change, so anytime a previously execed byte changes, make a new empty snapshot and start filling it in
// ie make a stack of snapshots
// start by making the basic element
struct mem_byte {
   uint8_t byte;           // value of this byte
   unsigned times_execed;  // times this byte was executed (eg if it is uninitialized or were in a loop)
};

// make an array of mem_bytes the length of the input buffer
//typedef std::vector<struct mem_byte> Snapshot;
struct Snapshot {
   std::vector<struct mem_byte> mem_bytes;
   float density;
   unsigned num_execed_bytes;
   unsigned min_addr;
   unsigned max_addr;
};
typedef std::vector<struct Snapshot> Mem_map;

struct Success {
   Trace trace;
   Mem_map mem_map;
   float overlay_density;
   float avg_density;
   uint64_t eip_addr;
};


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
      bool eip_valid;
      uint64_t eip_addr;
      uint64_t proc_id;
      bool sysc_valid;
      uint64_t sysc;
      std::vector<Success> successes;
   } cfg;
   
   DasosPreproc (S2E* s2e): Plugin (s2e) {}

   ~DasosPreproc () {
   }

   void initialize ();
   
   bool isInShell (uint64_t pc);
   bool areInsn_instancesEqual (struct insn_instance i1, struct insn_instance i2, Mem_map m);
   bool isTraceSubset (Trace needle, Trace haystack, Mem_map m);
   bool isTraceUnique (Trace t, Mem_map m);
   void getStats (struct Snapshot* s, unsigned len);
   void getSuccessStats (struct Success* s);
   
   void onCustomInstruction (S2EExecutionState* state, uint64_t opcode);
   void onActivateModule (S2EExecutionState* state);
   void onTranslateInstructionEnd (ExecutionSignal *signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc);
   void onSyscall (S2EExecutionState*, uint64_t, LinuxSyscallMonitor::SyscallType, uint32_t, LinuxSyscallMonitor::SyscallReturnSignal&);
   void onFini (S2EExecutionState* state);
   
   void printSuccess (struct Success s);
   void printTrace (Trace t, Mem_map m);
   void printInsn_instance (struct insn_instance insn, Mem_map m, unsigned idx, bool doDisasm);
   void printDisasm (uint8_t* raw, unsigned len);
   //void printDisasm_viaSystem (uint8_t* raw, unsigned len);
   void printDisasm_viaLib (uint8_t* raw, unsigned len);
   void printMemMap (Mem_map m, uint64_t base, unsigned len);
   void printSnapshot (struct Snapshot s, uint64_t base, unsigned len);
   
   unsigned times_execed (struct Snapshot* s, uint64_t pc);
   uint8_t byte (struct Snapshot* s, uint64_t pc);
   void times_execedInc (struct Snapshot* s, uint64_t pc);
   void byteWrite (struct Snapshot* s, uint64_t pc, uint8_t value);
   
   void fuzzFork (S2EExecutionState* state, unsigned int start, unsigned int end);
   void fuzzFork1 (S2EExecutionState* state, unsigned int value);
};



class DasosPreprocState: public PluginState {
private:
   // this is the variable used to maintain the connection signaled by s2e/qemu when an instruction has finished being processed by s2e/qemu
   sigc::connection oTICE_connection;
   bool oTICE_connected;
   
   // an array of insn pcs (plus lens and corresponding snapshots) appended as executed (in order of execution)
   Trace trace;
   
   // a stack of snapshots
   Mem_map mem_map;
   
   bool has_entered_shell;
   
public:
   DasosPreprocState ();
   DasosPreprocState (S2EExecutionState *s, Plugin *p);
   void pushSnapshot (unsigned len);
   virtual ~DasosPreprocState ();
   virtual PluginState *clone () const;
   static PluginState *factory (Plugin* p, S2EExecutionState* s);
   
   friend class DasosPreproc;
};

} // namespace plugins
} // namespace s2e

#endif
    

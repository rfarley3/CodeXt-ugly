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
#include <string>

#include <udis86.h>


#define MAX_SYSCALL_NUM 512
#ifndef UNKNOWNS
#define SYSC_UNKNOWN 1024
#define EIP_UNKNOWN 0
#define UNKNOWNS
#endif

// cap of insns executed in a row any time the ctrl flow goes into the range of the buffer
#define MAX_IN_RANGE_INSNS 10000
// cap of insns executed in a row any time the ctrl flow goes outside the buffer having had been in the buffer at least once
#define MAX_OUT_RANGE_INSNS 1000000
// cap of insns executed in a row any time the ctrl flow goes into the kernel but the kernel doesn't flush the TLB (overwrites reg CR3)---having had been in the buffer at least once and reset any time it goes back IoB or gets a non-kernel OoB insn
#define MAX_KERNEL_INSNS 1000000

// keep track of insns executed
// make an array of insns that become a trace
// start by defining an insn, leverage memory snapshots to avoid duplicating data
struct insn_instance {
   uint32_t snapshot_idx;  // which snapshot
   uint64_t pc;            // offset/pc of insn NOTE: within the snapshot (ie pc - cfg.base_addr)
   uint16_t len;           // num bytes of insn
   bool     in_range;      // whether it is in the range (ie if the bytes were recorded into the mem_map/snapshot
   bool     valid;         // whether it is an insn worth using in comparisons (ie is a repeat)
   //Store insn byte string... Maybe? Or llvm ir decoding? Or disasm?
};

// as insn are executed, add them to mem map snapshot stack,
//and then note which stack index as well as the pc and byte len within index
struct Trace {
   uint64_t in_range_insns;
   uint64_t valid_insns;
   uint64_t last_valid;
   std::vector<struct insn_instance> insns;
};
//   typedef std::vector<struct insn_instance> Trace;

// keep track of memory bytes executed as a memory map
// but they can change, so anytime a previously execed byte changes, make a new empty snapshot and start filling it in
// ie make a stack of snapshots
// start by making the basic element
struct mem_byte {
   uint8_t byte;           // value of this byte
   uint32_t times_execed;  // times this byte was executed (eg if it is uninitialized or were in a loop)
   bool validated;         // if the byte was used in a valid insn
};

// make an array of mem_bytes the length of the input buffer
//typedef std::vector<struct mem_byte> Snapshot;
struct Snapshot {
   std::vector<struct mem_byte> mem_bytes;
   float density;
   uint32_t num_execed_bytes;
   uint32_t num_valid_bytes;
   uint64_t min_addr;
   uint64_t max_addr;
};
typedef std::vector<struct Snapshot> Mem_map;

struct Success {
   Trace trace;
   Mem_map mem_map;
   float overlay_density;
   float avg_density;
   uint64_t eip_addr;
   uint32_t offset;   // the offset where the success happened
};


namespace s2e {
namespace plugins {

class DasosPreproc : public Plugin { 
   S2E_PLUGIN

private:
   sigc::connection * customInstructionConnection;
   
   /* Some Linux Memory Management notes:
    * Linux uses only 4 segments:
    *   -2 segments (code and data/stack) for KERNEL SPACE from [0xC000 0000] (3 GB) to [0xFFFF *FFFF] (4 GB)
    *   -2 segments (code and data/stack) for USER SPACE from [0] (0 GB) to [0xBFFF FFFF] (3 GB)
    * http://www.tldp.org/HOWTO/KernelAnalysis-HOWTO-7.html
    */
public:
   struct Cfg_ {
      bool is_loaded;
      uint64_t base_addr;
      uint64_t byte_len;
      uint64_t end_addr;  // yea I know it's redundant (base_addr+byte_len), but it's handy
      bool eip_valid;
      uint64_t eip_addr;
      uint64_t proc_id; // the s2e accessor fn getPid() returns the "page directory register" which is typically the high 20b of CR3
      // NOTE that in linux when the OS/kernel mode does something it uses the last known CR3 since kernel mapping exists within all procs
      // QEMU does not support system management mode (SMM) so no concern over code interrupt from it.
      //uint32_t proc_cr3;
      bool sysc_valid;
      uint64_t sysc;
      std::vector<Success> successes;
   } cfg;
   
   DasosPreproc (S2E* s2e): Plugin (s2e) {}

   ~DasosPreproc () {
   }

   void initialize ();
   
   bool isInShell (uint64_t pc);
   bool isInsnImpossibleFirst (uint8_t* raw_insn, unsigned raw_insn_len);
   bool areInsn_instancesEqual (struct insn_instance i1, struct insn_instance i2, Mem_map m);
   bool isInsnRepeat (struct insn_instance i2, struct insn_instance i1, Mem_map m);
   unsigned findNextInRange (Trace t, unsigned i);
   unsigned findNextValid (Trace t, unsigned i);
   bool isTraceSubset (Trace needle, Trace haystack, Mem_map m);
   bool isTraceUnique (Trace t, Mem_map m);
   void getStats (struct Snapshot* s, unsigned len);
   void getSuccessStats (struct Success* s);
   
   void terminateStateEarly_wrap (S2EExecutionState* state, std::string msg);
   void onCustomInstruction (S2EExecutionState* state, uint64_t opcode);
   void onActivateModule (S2EExecutionState* state);
   void printOOBDebug (S2EExecutionState* state);
   void validateInsn (struct insn_instance insn, uint8_t* raw, S2EExecutionState* state);
   void invalidateInsn (unsigned idx, struct insn_instance cause, S2EExecutionState* state);
   void onTransIOBInsns (S2EExecutionState* state, uint64_t pc, TranslationBlock *tb);
   void onTransOOBInsns (S2EExecutionState* state, uint64_t pc, TranslationBlock *tb);
   bool isInKernMode (uint64_t pc);
   void onTransKernInsns (S2EExecutionState* state, uint64_t pc);
   void onTranslateInstructionEnd (ExecutionSignal *signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc);
   void onSyscall (S2EExecutionState*, uint64_t, LinuxSyscallMonitor::SyscallType, uint32_t, LinuxSyscallMonitor::SyscallReturnSignal&);
   bool isInNormalizeMode (S2EExecutionState* state);
   void onFiniPreproc (S2EExecutionState* state);
   void onFini (S2EExecutionState* state);
   
   void printSuccess (struct Success s);
   void printTrace (Trace t, Mem_map m);
   void printOOBInsn (struct insn_instance insn, unsigned idx, S2EExecutionState* state);
   void printInsn_raw (uint8_t* raw, unsigned raw_len, bool doDisasm);
   void printInsn_instance (struct insn_instance insn, Mem_map m, unsigned idx, bool doDisasm);
   void printDisasm (uint8_t* raw, unsigned len);
   void printDisasmSingle (uint8_t* raw, unsigned len);
   void printMemMap (Mem_map m, uint64_t base, unsigned len);
   void printSnapshot (struct Snapshot s, uint64_t base, unsigned len);
   
   uint32_t times_execed (struct Snapshot* s, uint64_t pc);
   uint8_t byte (struct Snapshot* s, uint64_t pc);
   bool validated (struct Snapshot* s, uint64_t pc);
   void times_execedInc (struct Snapshot* s, uint64_t pc);
   void byteWrite (struct Snapshot* s, uint64_t pc, uint8_t value);
   void validate (struct Snapshot* s, uint64_t pc);
   void invalidate (struct Snapshot* s, uint64_t pc);
   
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
   
   bool has_entered_range;
   bool within_range;
   unsigned in_range_insns;
   unsigned out_range_insns;
   unsigned other_procs_insns;
   uint32_t offset;
   uint64_t kernel_insns;
   
public:
   DasosPreprocState ();
   DasosPreprocState (S2EExecutionState *s, Plugin *p);
   void appendSnapshot (unsigned len);
   virtual ~DasosPreprocState ();
   virtual PluginState *clone () const;
   static PluginState *factory (Plugin* p, S2EExecutionState* s);
   
   friend class DasosPreproc;
};

} // namespace plugins
} // namespace s2e

#endif
    

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
#include <fstream>

#include <udis86.h>


#define MAX_SYSCALL_NUM 512
#ifndef UNKNOWNS
#define SYSC_UNKNOWN 1024
#define EIP_UNKNOWN 0
#define UNKNOWNS
#endif

// cap of insns executed in a row any time the ctrl flow goes into the range of the buffer
#define MAX_IN_RANGE_INSNS  100000
// cap of insns executed in a row any time the ctrl flow goes outside the buffer having had been in the buffer at least once
#define MAX_OUT_RANGE_INSNS  10000
// cap of insns executed in a row any time the ctrl flow goes into the kernel but the kernel doesn't flush the TLB (overwrites reg CR3)---having had been in the buffer at least once and reset any time it goes back IoB or gets a non-kernel OoB insn
#define MAX_KERNEL_INSNS     10000
#define MAX_KILLABLE_INSNS   10000
#define CLUSTER_WRITES_BY       10
#define MIN_EXEC_INSNS           6
#define MIN_EXEC_BYTES          15

// keep track of memory bytes executed as a memory map
// but they can change, so anytime a previously used byte changes, make a new empty snapshot and start filling it in
// ie make a stack of snapshots
// start by making the basic element
struct mem_byte {
   uint8_t  byte;          // value of this byte
   uint32_t times_used;    // code? times this byte was executed (eg if it is uninitialized or were in a loop)
                           // data? then it is ignored (times_written is always only 1)
   bool     validated;     // if the byte was used in a valid insn
};


// keep track of insns executed
// make an array of insns that become a trace
// start by defining an insn, leverage memory snapshots to avoid duplicating data
struct event_instance_t {
   uint32_t snapshot_idx;  // which snapshot
   uint64_t seq_num;       // sequence number of instruction [in order of execution, or the executed insn that made this write]
   uint64_t addr;          // offset/pc of insn NOTE: within the snapshot (ie pc - cfg.base_addr)
   uint16_t len;           // num bytes of insn/data
   uint64_t next_pc;       // record what QEMU reports as the next PC to be executed
   uint64_t other_pc;      // if it's a jmp insn and the next_pc is sequential, find its jump addr
                           // if it's a data event, then this is the writer address
   bool     in_range;      // whether it is in the range (ie if the bytes were recorded into the code_map/snapshot
   bool     valid;         // whether it is an insn worth using in comparisons (ie is a repeat)
   uint64_t ti_seq_num;    // if it is an insn translation, then the insn's global monotonic increasing sequence number (nth trans'ed insn)
   uint64_t tb_seq_num;    // if it is an insn translation, then the trans block's global monotonic increasing sequence number (nth trans'ed tb)
   // uint32_t type;          // the type of the insn or data access
   std::vector<struct mem_byte> bytes; // the bytes translated or the value of the memory access
   std::string disasm;     // the disasm string of the translation
   //Store insn byte string... Maybe? Or llvm ir decoding? Or disasm?
};

typedef struct event_instance_t trans_instance;
typedef struct event_instance_t data_instance;
typedef struct event_instance_t exec_instance;

// as insn are executed, add them to mem map snapshot stack,
//and then note which stack index as well as the pc and byte len within index
struct Insn_Trace_t {
   uint64_t                    in_range_insns;
   uint64_t                    valid_insns;
   uint64_t                    last_valid;
   std::vector<trans_instance> insns;
};
typedef struct Insn_Trace_t Trans_Trace;
typedef struct Insn_Trace_t Exec_Trace;


// as insn are executed, add them to mem map snapshot stack,
// and then note which stack index as well as the pc and byte len within index
struct Data_Trace_t {
   uint64_t                   in_range_bytes;
   std::vector<data_instance> writes;
};
typedef struct Data_Trace_t Data_Trace;

// make an array of mem_bytes the length of the input buffer
struct Snapshot_t {
   std::vector<struct mem_byte> mem_bytes;
   float    density;
   uint32_t num_used_bytes;
   uint32_t num_valid_bytes;
   uint64_t min_addr;
   uint64_t max_addr;
};
typedef struct Snapshot_t     Snapshot;
typedef std::vector<Snapshot> Mem_map;


// be able to store a context at any given point
struct X86State {
   uint32_t eax;
   uint32_t ebx;
   uint32_t ecx;
   uint32_t edx;
   uint32_t esi;
   uint32_t edi;
   uint32_t ebp;
   uint32_t esp;
   uint32_t eip;
   uint32_t cr2;
};

// track all system calls that happen
struct Syscall_t {
   bool     success;   // if this matches given info, or if this syscall is merely part of a fragment
   uint64_t seq_num;   // execution sequence number of the int 0x80
   uint64_t addr;      // the address of the system call 
                       // duplicate info, can also be found by looking into exec_trace via seq_num
                       // use same method to get its ti_seq_num and tb_seq_num
   uint8_t  num;       // system call number (eax)
   struct X86State preState;  // state->dumpX86State
   struct X86State postState; // state->dumpX86State
   
};
typedef struct Syscall_t      Syscall;
typedef std::vector<Syscall>  Syscall_Trace;


struct Fragment_t {
   bool          is_success;
   Trans_Trace   trans_trace;
   Data_Trace    write_trace;
   Exec_Trace    exec_trace;
   Syscall_Trace call_trace;
   Mem_map       code_map;
   Mem_map       data_map;
   float         overlay_density;
   float         avg_density;
   //uint64_t      eip_addr;  // contained in call_trace
   uint32_t      offset;   // the offset where the success happened
   // make a vector of successes that are subsets of this one
};
typedef struct Fragment_t Success;  // fragment where is_success is true
typedef struct Fragment_t Fragment;  // fragment where is_success is false


typedef std::vector<Fragment_t> Chunk;


struct symbVar_t {
	std::string name;    // what name to use
	uint64_t    addr;    // what offset from start of shellcode to marl
	uint64_t    len;     // number of bytes to mark
	uint64_t    when;    // after x insn mark this mem addr
	bool        marked;  // has it been marked as symb
};


namespace s2e {
namespace plugins {

class DasosPreproc : public Plugin { 
   S2E_PLUGIN

private:
   sigc::connection  customInstructionConnection;
   

public:
   struct Cfg_ {
      bool     is_loaded;
      uint64_t base_addr;
      uint64_t byte_len;
      uint64_t end_addr;  // yea I know it's redundant (base_addr+byte_len), but it's handy
      bool     eip_valid;
      uint64_t eip_addr;
      uint64_t proc_id; // the s2e accessor fn getPid() returns the "page directory register" which is typically the high 20b of CR3
      // NOTE that in linux when the OS/kernel mode does something it uses the last known CR3 since kernel mapping exists within all procs
      // QEMU does not support system management mode (SMM) so no concern over code interrupt from it.
      bool     sysc_valid;   // if goal sysc num was given
      uint64_t sysc;         // goal system call number to look for
      bool     multiSysc;    // if multiple system calls are permitted (or just stop at first)
      bool     has_printed;  // whether or not the system has printed a copy of the buffer to the output file. do it on the initDataMap for the 1st state
      //bool     has_forked;   // whether or not the first state has created the symb and cond variables
      //klee::ref<klee::Expr> symb;// = state->createSymbolicValue (klee::Expr::Int32, "fuzz_symb");
      //klee::ref<klee::Expr> cond;// = klee::NeExpr::create (symb, klee::ConstantExpr::create (value, klee::Expr::Int32) );
		uint64_t clusterWritesBy;
		uint64_t minExecInsns;
		uint64_t minExecBytes;
		uint64_t maxInRangeInsn;
		uint64_t maxOutRangeInsn;
		uint64_t maxKernelInsn;
		uint64_t maxKillableInsn;
      std::vector<Success>   successes;
      std::vector<Fragment>  fragments;
      std::vector<Chunk>     chunks;
		std::vector<symbVar_t> symbVars;
		std::vector<symbVar_t> monitorVars;  
		bool enableMultipath;
   } cfg;
   
   DasosPreproc (S2E* s2e): Plugin (s2e) {}

   ~DasosPreproc () {
      customInstructionConnection.disconnect ();
   }

   void initialize ();
   
   // Important or commonly called functions
   // is pc within the range we marked by onActivateModule
   bool isInShell (uint64_t pc);      
   // is pc within Linux kernel address ranges
   bool isInKernMode (uint64_t pc);   
   /* Some Linux Memory Management notes:
   * Linux uses only 4 segments:
   *   -2 segments (code and data/stack) for KERNEL SPACE from [0xC000 0000] (3 GB) to [0xFFFF *FFFF] (4 GB)
   *   -2 segments (code and data/stack) for USER SPACE from [0] (0 GB) to [0xBFFF FFFF] (3 GB)
   * http://www.tldp.org/HOWTO/KernelAnalysis-HOWTO-7.html
   */
   // given 8b blob (eg uint8_t or unsigned char) return signed int value
   int8_t signed1Byte (uint8_t b);    
   // when we terminateStateEarly we want to disconnect all the signals and do some housekeeping
   void terminateStateEarly_wrap (S2EExecutionState* state, std::string msg, bool possible_success);
   bool anySuccess (Syscall_Trace t);
   
   // Helper functions
   bool     isInsnImpossibleFirst (uint8_t* raw_insn, unsigned raw_insn_len);
   bool     areInsnInstancesEqual (exec_instance i1, exec_instance i2); 
   unsigned findNextValid         (Exec_Trace t, unsigned i);
   bool     hasBeenTranslated     (S2EExecutionState* state, uint64_t pc, uint64_t addr, unsigned len);
   
   
   // CustomInstruction
   /* This is called by S2E when it finds a custom insn, it is up to this instruction to filter out 
    * prefixes that are for other plugins, and then switch on an opcode to decode what specific
    * insn it is. For our plugin there are the following possibilities:
    *  - s2e_dasospreproc_init
    *  - s2e_dasospreproc_fuzz
    *  - s2e_dasospreproc_createFork
    *  - s2e_dasospreproc_fini 
    *  - s2e_dasospreproc_enableMulti 
    */
   void onCustomInstruction (S2EExecutionState* state, uint64_t opcode);

   // ActivateModule (s2e_dasospreproc_init)
   // sets up the buffer boundaries and all the hooks (oDMA, oTIE, oTBE, oTBS, oPC, oExc, oPF, oTJS)
   void onActivateModule (S2EExecutionState* state);
   
   
   // Fini (s2e_dasospreproc_fini)
   // When the initial state (the forker) realizes that it has no more states to fork (processing is done)
   void onFini        (S2EExecutionState* state);
   void onFiniPreproc (S2EExecutionState* state);
   void dumpPreproc   (S2EExecutionState* state);
   
   
   // TranslateBlockEnd
   // Update next_pc and length appropriately, sets hook for onExecBlock
   void onTranslateBlockEnd (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, bool is_target_valid, uint64_t target_pc);
   
   
   // S2E event hooks that currently exist jut for debug output
   void onExecuteBlock        (S2EExecutionState* state, uint64_t pc);
   void onTranslateBlockStart (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc);
   void onPrivilegeChange     (S2EExecutionState* state, unsigned prev_level, unsigned curr_level);
   void onPageFault           (S2EExecutionState* state, uint64_t, bool);
   void onTranslateJumpStart  (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, int jump_type);
   
   
   // Exception
   // Detects if executed instruction issues a software interrupt, ie syscall detection
   void onException       (S2EExecutionState* state, unsigned exception_idx, uint64_t pc);
   void onSyscall         (S2EExecutionState* state, uint64_t pc, uint32_t sysc_number);
   bool isEndOfPath       (unsigned num);
   void dumpX86State      (S2EExecutionState* state, struct X86State& s);
   bool isInNormalizeMode (S2EExecutionState* state); // is this a non-forking run (state0 got a syscall IOB)
   bool isExecTraceSubset (Exec_Trace needle, Exec_Trace haystack);
   bool isInsnTraceUnique (Exec_Trace t, std::vector<struct Fragment_t> f); 
   void onSuccess         (S2EExecutionState* state, uint64_t pid, uint64_t pc, uint32_t sysc_number, unsigned len);
   void getSuccessStats   (Success& s);
   void onFragment        (S2EExecutionState* state, uint64_t pid, uint64_t pc, uint32_t sysc_number, unsigned len);
   void onSuccess         (S2EExecutionState* state);
   void onFragment        (S2EExecutionState* state);
   void printSuccess      (Success s);
   void printFragment     (Fragment f);
   void printFragment_t   (struct Fragment_t f);
   void printCallTrace    (Syscall_Trace t);
   void printSyscallInstance (Syscall s);
   void printX86State     (struct X86State s);
   
   Chunk mergeChunks      (Chunk before, Chunk after);
   void  createCodeChunks (unsigned match_frag);
   void  printCodeChunks  ();
   void  printChunk       (Chunk c);
   
   
   // DataMemoryAccess
   // Detects writes to memory within monitored buffer. Adds write to write_trace.
   void initDataMap        (S2EExecutionState* state);
   void onDataMemoryAccess (S2EExecutionState* state, klee::ref<klee::Expr> virtualAddress, klee::ref<klee::Expr> hostAddress, klee::ref<klee::Expr> value, bool isWrite, bool isIO);
   void printDataTrace     (Data_Trace d);
   void printWriteInstance (data_instance w);
   void mapWrites          (Mem_map& m, Data_Trace d);
   
   
   // TranslateInstruction
   // Determines where insn is and gathers info about it, then calls IOB/OOB/Kern helper
   // Catches out of control (OOB for too long, unexpected jumps) paths
   void onTranslateInstructionEnd (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t nextpc);
   void printTransTrace           (Trans_Trace t);
   void printTransInstance        (trans_instance insn);
   
   
   // Translate Instruction Helpers. 
   // IOB = in bounds (an insn within the shellcode). 
   // Sets hook for onExecInsn. 
   // Adds insn to trans_trace. 
   // Records meta-data on instructions for onExec's exec_trace.
   void onTransIOBInsns  (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t len, uint64_t nextpc);
   // OOB = out of bounds (all other insns)
   void onTransOOBInsns  (S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t len, uint64_t nextpc);
   void printOOBInsn     (S2EExecutionState* state, trans_instance insn, unsigned num_oob);
   void printOOBDebug    (S2EExecutionState* state);
   // Kern = kernel insns (subset of OOB with PC that correspond to kernel addresses).
   void onTransKernInsns (S2EExecutionState* state, uint64_t pc);
   
   
   // ExecutionSignal
   // Detects IOB insn execution. Adds insn to exec_trace.
   void     onExecuteInsn     (S2EExecutionState* state, uint64_t pc);
	void     markSymb          (S2EExecutionState* state, struct symbVar_t svar);
   void     markSymb          (S2EExecutionState* state, uint32_t address, std::string nameStr);
   void     markExecutableSymb(S2EExecutionState* state, uint32_t address, std::string nameStr);
   bool     isSymb            (S2EExecutionState* state, uint32_t address);
   bool     isSymb_extended   (S2EExecutionState* state, uint32_t address, uint8_t& conc_val, klee::ref<klee::Expr>& symb_val);
   void     printSymb         (S2EExecutionState* state, uint32_t address);
   void     handleIfFPU       (S2EExecutionState* state, exec_instance e);
   uint64_t findWriteAddr     (uint64_t writer, Data_Trace t);
   void     printExecTrace    (Exec_Trace e);
   void     printExecInstance (exec_instance insn);
   void     mapExecs          (Mem_map& m, Exec_Trace e);
   
   
   // Generic printing
   void        printMem_raw       (uint8_t* raw, unsigned raw_len, uint64_t base);
   void        printInsn_raw      (uint8_t* raw, unsigned raw_len, bool doDisasm);
   void        printEventInstance (event_instance_t insn);
   void        printDisasm        (uint8_t* raw, unsigned len);
   void        printDisasmSingle  (uint8_t* raw, unsigned len);
   std::string getDisasmSingle    (uint8_t* raw, unsigned len);
   std::string getDisasmSingle    (std::vector<struct mem_byte> bytes);
   
   
   // Mem_map interaction and accessors
   void     printSnapshot  (Snapshot s, uint64_t base, bool force_print);
   void     printMemMap    (Mem_map m, uint64_t base);
   void     appendSnapshot (Mem_map& map, unsigned len);
   uint32_t timesUsed      (Snapshot s, uint64_t pc);
   uint8_t  byte           (Snapshot s, uint64_t pc);
   bool     validated      (Snapshot s, uint64_t pc);
   void     timesUsedInc   (Snapshot& s, uint64_t pc);
   void     byteWrite      (Snapshot& s, uint64_t pc, uint8_t value);
   void     validate       (Snapshot& s, uint64_t pc);
   void     invalidate     (Snapshot& s, uint64_t pc);
   
   
   // Use to control S2E forking (s2e_dasospreproc_fuzz) (s2e_dasospreproc_createFork)
   void fuzzFork  (S2EExecutionState* state, unsigned int start, unsigned int end);
   void fuzzFork1 (S2EExecutionState* state, unsigned int value);
   void fuzzFork2 (S2EExecutionState* state, unsigned int value);
};



class DasosPreprocState: public PluginState {
private:
   // this is the variable used to maintain the connection signaled by s2e/qemu when an instruction has finished being processed by s2e/qemu
   sigc::connection oTIE_connection;     // onTranlateInstructionEnd
   bool             oTIE_connected;
   sigc::connection oTBE_connection;     // onTranslateBlockEnd
   bool             oTBE_connected;
   sigc::connection oTBS_connection;     // onTranslateBlockStart
   bool             oTBS_connected;
   sigc::connection oDMA_connection;     // onDataMemoryAccess
   bool             oDMA_connected;
   sigc::connection oPC_connection;      // onPrivilegeChange
   sigc::connection oExc_connection;     // onException
   sigc::connection oPF_connection;      // onPageFault
   sigc::connection oTJS_connection;     // onTranslateJumpStart
   bool             debugs_connected;
   
   bool flushTbOnChange;  // onActivate enables this, if true, then if a prev translated insn within the same basic block is written to, then the TB is retranslated
   
   // an array of insn pcs (plus lens and corresponding snapshots) appended as executed (in order of execution)
   Trans_Trace   trans_trace;
   Exec_Trace    exec_trace;
   Data_Trace    write_trace;
   Syscall_Trace sysc_trace;
   
   // a stack of snapshots
   Mem_map code_map;  // map of insns executed
   Mem_map data_map;  // map of writes
   
   uint64_t seq_num;                        // executed insn sequence number
   uint64_t ti_seq_num;                     // translated intruction sequence number
   uint64_t tb_seq_num;                     // translation block sequence number
   bool     has_entered_range;              // we have encountered the buffer range at least once
   bool     within_range;                   // we are currently in buffer range
   unsigned in_range_insns;                 // number of trans in range insns
   unsigned out_range_insns;                // number of trans out of range insns
   unsigned other_procs_insns;              // number of trans other proc insns
   unsigned tot_killable_insns;             // number of insns towards killable count
   uint32_t offset;                         // tracks PC/EIP as an offset within shell/buffer
   uint64_t kernel_insns;                   // number of insns in kernel
   unsigned execed_insns;                   // number of executed insns
   uint64_t pc_of_next_insn_from_last_IoB;  // expected next insn once buffer execution picks back up
   uint64_t pc_of_next_insn;                // what the address of the next insn should be
   bool     expecting_jmp_OOB;              // whether or not we were expecting this insn to be OOB
   uint64_t syscall_cnt;                    // we have found a syscall, count of syscalls found
   uint64_t oTBE_nextpc;                    // if this is a TBE we need to record the next pc, so oTIE can know insn.next_pc accurately
   uint64_t last_fpu_pc;                    // anytime a fpu insn is executed store its pc here
   uint64_t oEI_retranslate;
   bool     has_created_symb;               // if state0 has created the symb/cond used to fork
   klee::ref<klee::Expr> symb;
   bool     has_created_fuzz_cond;          // if state0 has created the cond used to fork
   klee::ref<klee::Expr> fuzz_cond;
   bool     x_is_symb;
   
public:
   DasosPreprocState ();
   DasosPreprocState (S2EExecutionState* s, Plugin* p);
   virtual ~DasosPreprocState ();
   virtual PluginState* clone () const;
   static PluginState* factory (Plugin* p, S2EExecutionState* s);
   
   friend class DasosPreproc;
};

} // namespace plugins
} // namespace s2e

#endif
    

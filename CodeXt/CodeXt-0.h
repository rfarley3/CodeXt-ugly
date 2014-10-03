#ifndef S2E_PLUGINS_CODEXT_H
#define S2E_PLUGINS_CODEXT_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/LinuxSyscallMonitor.h>
#include "ExecutionTracers/ExecutionTracer.h"
#include <klee/Solver.h>

#include <vector>
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <fstream>
#include <bitset>

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

// what if there was klee::ref<klee::Expr> byte_expr and std::vector<uint64_t> taints


// keep track of insns executed
// make an array of insns that become a trace
// start by defining an insn, leverage memory snapshots to avoid duplicating data
struct event_instance_t {
   uint32_t snapshot_idx;  // which snapshot
   uint64_t seq_num;       // sequence number of instruction [in order of execution, or the executed insn that made this write]
	uint8_t  is_register;   // whether the addr is a register offset, or the nth byte within the array, used in data events
   uint64_t addr;          // offset/pc of insn NOTE: within the snapshot (ie pc - cfg.base_addr)
	// if it's an is_register (0..7) then addr is the CPU_OFFSET(regs[R_<reg>]), which is an absolute address
   uint16_t len;           // num bytes of insn/data
   uint64_t next_pc;       // record what QEMU reports as the next PC to be executed
									// if this is a taint event, then this is the taint source
   uint64_t other_pc;      // if it's a jmp insn and the next_pc is sequential, find its jump addr
                           // if it's a data event, then this is the writer address
	bool     is_write;      // if it's a data event, then if this is a write (vs read)
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

typedef std::vector<data_instance> Reg_Access_Trace;
typedef std::vector<uint64_t>      Silent_Concretize_Trace;

struct Taint_Trace_t {
	klee::ref<klee::Expr>      label;
	std::vector<data_instance> events;
};
typedef struct Taint_Trace_t Taint_Trace;

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


struct Mem_map_t {
	std::string           name;
	std::vector<Snapshot> snaps;
};
typedef struct Mem_map_t Mem_map;


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
   bool                 is_success;
   Trans_Trace          trans_trace;
   Data_Trace           write_trace;
   Exec_Trace           exec_trace;
   Syscall_Trace        call_trace;
   Mem_map              code_map;
   Mem_map              data_map;
	std::vector<Mem_map> taint_maps;
   float                overlay_density;
   float                avg_density;
   //uint64_t           eip_addr;  // contained in call_trace
   uint32_t             offset;   // the offset where the success happened
   // make a vector of successes that are subsets of this one
};
typedef struct Fragment_t Success;  // fragment where is_success is true
typedef struct Fragment_t Fragment;  // fragment where is_success is false


typedef std::vector<Fragment_t> Chunk;


struct symb_var_t {
	std::string name;    // what name to use
	uint64_t    addr;    // what offset from start of shellcode to mark as symbolic
	uint64_t    len;     // number of bytes to mark
	uint64_t    when;    // after x insn mark this mem addr
	bool        marked;  // has it been marked as symb
	std::vector <klee::ref <klee::Expr> > exprs;  // vector of len length, each element is the offset from addr's byte's symbolic expression
	std::vector <klee::ref <klee::Expr> > labels; // vector of len length, each element is the offset from addr's byte's label used in its symbolic expression
};


/*struct regWrite_t {
	uint64_t pc;
	uint8_t reg;
};*/

struct label_str_to_expr {
	std::string label;
	klee::ref<klee::Expr> expr;
};
typedef std::vector<struct label_str_to_expr> Label_Table;


namespace s2e {
namespace plugins {

class CodeXt : public Plugin { 
   S2E_PLUGIN

private:
   sigc::connection  custom_instruction_connection;
   

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
      bool     allow_multi_sysc;    // if multiple system calls are permitted (or just stop at first)
      bool     has_printed;  // whether or not the system has printed a copy of the buffer to the output file. do it on the initDataMap for the 1st state
      //bool     has_forked;   // whether or not the first state has created the symb and cond variables
      //klee::ref<klee::Expr> symb;// = state->createSymbolicValue (klee::Expr::Int32, "fuzz_symb");
      //klee::ref<klee::Expr> cond;// = klee::NeExpr::create (symb, klee::ConstantExpr::create (value, klee::Expr::Int32) );
		uint64_t cluster_writes_by;
		uint64_t min_exec_insns;
		uint64_t min_exec_bytes;
		uint64_t max_in_range_insn;
		uint64_t max_out_range_insn;
		uint64_t max_kernel_insn;
		uint64_t max_killable_insn;
      std::vector<Success>   successes;
      std::vector<Fragment>  fragments;
      std::vector<Chunk>     chunks;
		std::vector<symb_var_t> symb_vars;
		std::vector<symb_var_t> monitor_vars;  
		bool enable_multipath;
   } cfg;

	static const char * const X86_REG_NAMES[];
   
   CodeXt (S2E* s2e): Plugin (s2e) {}

   ~CodeXt () {
      custom_instruction_connection.disconnect ();
   }

   void initialize ();
	struct symb_var_t getSymbVar (std::vector<std::string> symb_data, unsigned& i);
	
	// prints a hex string of the val given at proper byte length
	//std::ostringstream hex (unsigned int bytes, uint64_t val);
	std::string hex (unsigned int bytes, uint64_t val, bool showbase = 1);
	std::string hex (unsigned int bytes, klee::ref<klee::ConstantExpr> const_val);
	std::string bin (unsigned int bits, uint64_t val, bool showbase = 1);

	uint32_t              getTopOfStack (S2EExecutionState* state);
	bool                  readMemory    (S2EExecutionState* state, uint64_t address, void* buf, uint64_t size);
	klee::ref<klee::Expr> readMemory8   (S2EExecutionState* state, uint64_t addr);
	klee::ref<klee::Expr> read8         (S2EExecutionState* state, uint64_t pc, bool is_reg);
	void                  write8        (S2EExecutionState* state, uint64_t pc, klee::ref<klee::Expr> e, bool is_reg);
   
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
   int8_t toSignedByte (uint8_t b);    
   // when we terminateStateEarly we want to disconnect all the signals and do some housekeeping
   void terminateStateEarly_wrap (S2EExecutionState* state, std::string msg, bool possible_success);
   bool anySuccess (Syscall_Trace t);
   
   // Helper functions
   bool     isInsnImpossibleFirst (uint8_t* raw_insn, unsigned raw_insn_len);
   unsigned findNextValid         (Exec_Trace t, unsigned i);
   bool     hasBeenTranslated     (S2EExecutionState* state, uint64_t pc, uint64_t addr, unsigned len);
   uint64_t getTranslatedPc       (S2EExecutionState* state, uint64_t byte_addr);
   
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
   
	void monitorAddresses (S2EExecutionState* state, std::vector<uint64_t> addresses);
   
   // S2E event hooks that currently exist jut for debug output
   void onExecuteBlock        (S2EExecutionState* state, uint64_t pc);
   void onTranslateBlockStart (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc);
   void onPrivilegeChange     (S2EExecutionState* state, unsigned prev_level, unsigned curr_level);
   void onPageFault           (S2EExecutionState* state, uint64_t, bool);
   void onTranslateJumpStart  (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, int jump_type);
   
	// Taint tracing helpers
	//void                               onSilentConcretize_old (S2EExecutionState* state, uint64_t concretized_byte_addr, uint8_t concrete_val, const char* reason);
	void                                 onSilentConcretize     (S2EExecutionState* state, uint64_t addr, klee::ref<klee::Expr> pre_concrete_expr, uint8_t post_concrete_val, const char* reason);
	void                                 remOnSCConstraints     (S2EExecutionState* state);
	//klee::ref<klee::Expr>              getOriginalTaint       (uint64_t pc);
	klee::ref<klee::Expr>                getOriginalTaintLabel  (uint64_t pc);
	klee::ref<klee::Expr>                scrubLabels            (S2EExecutionState* state, klee::ref<klee::Expr> e); // remove all labels in e
	void                                 tidyAddr               (S2EExecutionState* state, uint64_t pc, bool is_reg);
	void                                 tidyReg32              (S2EExecutionState* state, uint64_t reg_offset);
	void                                 tidyReg8               (S2EExecutionState* state, uint64_t reg_offset);
	void                                 tidyMem                (S2EExecutionState* state, uint64_t pc);
	klee::ref<klee::Expr>                simplifyLabeledExpr    (S2EExecutionState* state, klee::ref<klee::Expr> e, bool do_prop = false);
	bool                                 allOps8                (klee::ref<klee::Expr> e);
	bool                                 isNoExtracts           (klee::ref<klee::Expr> e);
	bool                                 isOpBitwise            (klee::Expr::Kind k);
	bool                                 handleOp               (unsigned offset, klee::ref<klee::Expr> e, std::vector<klee::ref<klee::Expr> >& labels, bool is_bitwise = true);
	bool                                 opExtract8             (klee::ref<klee::Expr> e, std::vector<klee::ref<klee::Expr> >& labels);
	bool                                 opBitwise              (unsigned offset, klee::ref<klee::Expr> e, std::vector<klee::ref<klee::Expr> >& labels);
	bool                                 opNonBitwise           (unsigned offset, klee::ref<klee::Expr> e, std::vector<klee::ref<klee::Expr> >& labels);
	bool                                 isLabeledExprLeaf      (klee::ref<klee::Expr> e);
	bool                                 opConcat               (unsigned offset, klee::ref<klee::Expr> e, std::vector<klee::ref<klee::Expr> >& labels, bool is_bitwise);
	//klee::ref<klee::Expr>              deConcatLabel          (klee::ref<klee::Expr> c_e, unsigned offset);
	klee::ref<klee::Expr>                tidyLabels             (S2EExecutionState* state, klee::ref<klee::Expr> e); // simplify e, retaining labels
	klee::ref<klee::Expr>                labelExpr              (klee::ref<klee::Expr> e, klee::ref<klee::Expr> label); // taint e with label
	bool                                 isLabelSimplerForm     (klee::ref<klee::Expr> haystack, klee::ref<klee::Expr> needle);
	std::vector<klee::ref<klee::Expr> >  labelVectorAdd         (std::vector<klee::ref<klee::Expr> >& ls, std::vector<klee::ref<klee::Expr> > ls_to_add);
	std::vector<klee::ref<klee::Expr> >  labelVectorAdd         (std::vector<klee::ref<klee::Expr> >& ls, klee::ref<klee::Expr> l);
	std::vector< klee::ref<klee::Expr> > getLabels              (klee::ref<klee::Expr> e); // from any given expr
	std::string                          getLabelStr            (klee::ref<klee::Expr> e); // from a single ReadExpr
	klee::ref<klee::Expr>                createSymbolicValue    (S2EExecutionState* state, std::string label_str);
	bool                                 getExpr                (S2EExecutionState* state, klee::ref<klee::Expr>& e, std::string l); // from Label_Table
	bool                                 getLabel               (S2EExecutionState* state, std::string& l, klee::ref<klee::Expr> e); // from Label_Table
   std::string                          getBaseLabelStr        (std::string s);
	std::string                          trimLabelStr           (std::string s);
	void                                 searchAndReplaceRegsABCD (S2EExecutionState* state, klee::ref<klee::Expr> old_e, klee::ref<klee::Expr> new_e);
	klee::ref<klee::Expr>                searchAndReplace       (klee::ref<klee::Expr> haystack, klee::ref<klee::Expr> old_e, klee::ref<klee::Expr> new_e);
	//void                               enforceTaints          (S2EExecutionState* state);
	klee::ref<klee::Expr>                getPropLabel           (S2EExecutionState* state, klee::ref<klee::Expr> label);
	klee::ref<klee::Expr>                getPropLabel           (S2EExecutionState* state, std::string label_str);
	void                                 enforceTaints          (S2EExecutionState* state, std::vector<data_instance> reg_writes, std::vector<data_instance> data_writes);
	void                                 enforceTaintsAddr      (S2EExecutionState* state, std::vector<data_instance> writes, bool is_reg);
	void                                 enforceTaintsAddr      (S2EExecutionState* state, data_instance write, bool is_reg);
	void                                 enforceTaintsAddrold      (S2EExecutionState* state, std::vector<data_instance> writes, bool is_reg);
	void                                 enforceTaintsAddrold      (S2EExecutionState* state, data_instance write, bool is_reg);
	//void                               enforceTaintsMem       (S2EExecutionState* state, std::vector<data_instance> writes);
	//void                               enforceTaintsReg       (S2EExecutionState* state, std::vector<data_instance> reg_writes);
	void                                 taintMem               (S2EExecutionState* state, uint64_t dest_addr, uint64_t concretized_addr);
	void                                 taintMem               (S2EExecutionState* state, uint64_t dest_pc, uint8_t len, std::vector<klee::ref<klee::Expr> > labels);
	void                                 taintMem               (S2EExecutionState* state, uint64_t dest_addr, uint8_t len, klee::ref<klee::Expr> label);
	void                                 taintReg               (S2EExecutionState* state, uint64_t reg_offset, uint8_t len, std::vector<klee::ref<klee::Expr> > labels);
	//void                               taintReg               (S2EExecutionState* state, uint64_t reg_offset, std::string label_str);
	//void                               taintReg               (S2EExecutionState* state, uint8_t reg, uint64_t offset, uint64_t concretized_addr);
	void                                 taintReg               (S2EExecutionState* state, uint64_t reg_offset, uint8_t len, klee::ref<klee::Expr> label);
	void                                 taintAddr              (S2EExecutionState* state, uint64_t addr, uint8_t len, klee::ref<klee::Expr> label, bool is_reg);
	void                                 scrubMem               (S2EExecutionState* state, uint64_t pc, uint8_t len);
	void                                 scrubReg               (S2EExecutionState* state, uint64_t reg_offset, uint8_t len);
	void                                 scrubAddr              (S2EExecutionState* state, uint64_t addr, uint8_t len, bool is_reg);
	//klee::ref<klee::Expr>              extractLabel           (S2EExecutionState* state, klee::ref<klee::Expr> tainted_expr);
	std::string                          getInsnDisasm          (S2EExecutionState* state, uint64_t pc);
	bool                                 isInsnSubstr           (S2EExecutionState* state, std::string disasm, std::string s);
	bool                                 isInsnSubstr           (S2EExecutionState* state, uint64_t pc, std::string s);
	bool                                 isTaintDoNothingInsn   (S2EExecutionState* state, std::string disasm);
	bool                                 isTaintScrubbingInsn   (S2EExecutionState* state, std::string disasm);
	bool                                 isTaint1To1Insn        (S2EExecutionState* state, std::string disasm);
	uint8_t                              isImmSrcInsn           (std::vector<struct mem_byte> bytes);
	uint8_t                              regAddressingType      (S2EExecutionState* state, std::string disasm);
	bool                                 isInsnMov              (std::string disasm);
	//uint8_t                            isInsnMov              (S2EExecutionState* state, uint64_t pc);
	
   
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
   void initDataMap                 (S2EExecutionState* state);
	bool isRegABCD                   (uint8_t reg);
	uint8_t  getRegIndex             (std::string reg);
	uint64_t getRegOffset            (uint8_t reg);
	void addRegAccess                (uint64_t pc, uint8_t reg, uint64_t offset, uint64_t seq_num, Reg_Access_Trace &trace, bool is_write);
	//data_instance getRegWrite      (S2EExecutionState* state, uint64_t addr);
	void onTranslateRegisterAccess   (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t rmask, uint64_t wmask, bool accessesMemory);
	void onRegisterAccess            (S2EExecutionState* state, uint64_t pc);
   void onDataMemoryAccess          (S2EExecutionState* state, klee::ref<klee::Expr> virtualAddress, klee::ref<klee::Expr> hostAddress, klee::ref<klee::Expr> value, bool isWrite, bool isIO);
   void printDataTrace              (Data_Trace d);
   void printWriteInstance          (data_instance w);
   void mapWrites                   (Mem_map& m, Data_Trace d);
   
   
   // TranslateInstruction
   // Determines where insn is and gathers info about it, then calls IOB/OOB/Kern helper
   // Catches out of control (OOB for too long, unexpected jumps) paths
   void onTranslateInstruction      (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t nextpc, bool is_start);
   void onTranslateInstructionStart (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc);
   void onTranslateInstructionEnd   (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t nextpc);
   void printTransTrace             (Trans_Trace t);
   void printTransInstance          (trans_instance insn);
   
   
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
	void     onExecuteInsnStart (S2EExecutionState* state, uint64_t pc);
   void     onExecuteInsnEnd   (S2EExecutionState* state, uint64_t pc);
	void     symbolizeVars      (S2EExecutionState* state);
	void     monitorVars        (S2EExecutionState* state);
	void     monitorRegister    (S2EExecutionState* state, struct symb_var_t s);
	void     monitorMemByte     (S2EExecutionState* state, struct symb_var_t s, unsigned offset);
	void     markSymb           (S2EExecutionState* state, struct symb_var_t svar);
   //void     markSymb           (S2EExecutionState* state, uint32_t address, std::string nameStr);
	//void     markSymbConstraint (S2EExecutionState* state, uint32_t address, std::string nameStr);
	klee::ref<klee::Expr>      markSymbTagged     (S2EExecutionState* state, uint32_t address, std::string nameStr);
	klee::ref<klee::Expr>      markSymbTagged     (S2EExecutionState* state, uint32_t address, klee::ref<klee::Expr> label);
	//void     marksSymbAddConstExpr (S2EExecutionState* state, uint32_t address, std::string nameStr);
   bool     isSymb                (S2EExecutionState* state, uint32_t address);
   bool     isSymb_extended       (S2EExecutionState* state, uint32_t address, uint8_t& conc_val, klee::ref<klee::Expr>& symb_val);
   void     printSymb             (S2EExecutionState* state, uint32_t address);
   void     handleIfFPU           (S2EExecutionState* state, exec_instance e);
   uint64_t findWriteAddr         (uint64_t writer, Data_Trace t);
	
	// Execution trace output
   void     printExecTrace     (Exec_Trace e);
   void     printExecInstance  (exec_instance insn);
   void     mapExecs           (Mem_map& m, Exec_Trace e);
   
   void          initEventInstance     (event_instance_t& e);
   bool          areInsnInstancesEqual (exec_instance i1, exec_instance i2); 
	exec_instance getLastInRangeExec    (S2EExecutionState* state);
	
	// Taint trace output
	void    mapTaints (S2EExecutionState* state, std::vector<Mem_map>& ms);
	Mem_map mapTaint  (S2EExecutionState* state, klee::ref<klee::Expr> label);
	void    simplifyMemory       (S2EExecutionState* state);
	void    simplifyAddr         (S2EExecutionState* state, uint64_t pc, bool is_reg);
	bool    doesExprContainLabel (klee::ref<klee::Expr> e, std::string l_str);
	bool    doesExprContainLabel (klee::ref<klee::Expr> e, klee::ref<klee::Expr> l);
	
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



class CodeXtState: public PluginState {
private:
   // this is the variable used to maintain the connection signaled by s2e/qemu when an instruction has finished being processed by s2e/qemu
   sigc::connection oTIE_connection;     // onTranlateInstructionEnd
	sigc::connection oTIS_connection;     // onTranslateInstructionStart
   bool             oTIE_connected;
   sigc::connection oTBE_connection;     // onTranslateBlockEnd
   bool             oTBE_connected;
   sigc::connection oTBS_connection;     // onTranslateBlockStart
   bool             oTBS_connected;
   sigc::connection oDMA_connection;     // onDataMemoryAccess
	sigc::connection oRA_connection;      // onRegisterAccess
   bool             oDMA_connected;
	sigc::connection oSC_connection;      // onSilentConcretization
   bool             oSC_connected;
   sigc::connection oPC_connection;      // onPrivilegeChange
   sigc::connection oExc_connection;     // onException
   sigc::connection oPF_connection;      // onPageFault
   sigc::connection oTJS_connection;     // onTranslateJumpStart
   bool             debugs_connected;
   
   bool flush_tb_on_change;  // onActivate enables this, if true, then if a prev translated insn within the same basic block is written to, then the TB is retranslated
   
   // an array of insn pcs (plus lens and corresponding snapshots) appended as executed (in order of execution)
   Trans_Trace     trans_trace;
   Exec_Trace      exec_trace;
   Data_Trace      write_trace;
	//Data_Trace      curr_tb_data_trace;
	Data_Trace      last_insn_data_write_trace;
   Syscall_Trace   sysc_trace;
	
	Reg_Access_Trace         curr_tb_reg_trace;
	Reg_Access_Trace         last_insn_reg_write_trace;
	Silent_Concretize_Trace  concretize_trace;
	//std::vector<Taint_Trace> taint_traces;
	
   // a stack of snapshots
   Mem_map code_map;  // map of insns executed
   Mem_map data_map;  // map of writes
	std::vector<Mem_map> taint_maps;
   
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
   bool                  has_created_symb;               // if state0 has created the symb/cond used to fork
   klee::ref<klee::Expr> symb;
   bool                  has_created_fuzz_cond;          // if state0 has created the cond used to fork
   klee::ref<klee::Expr> fuzz_cond;
   bool                  x_is_symb;
	Label_Table           labels;
   
public:
   CodeXtState ();
   CodeXtState (S2EExecutionState* s, Plugin* p);
   virtual ~CodeXtState ();
   virtual PluginState* clone () const;
   static PluginState* factory (Plugin* p, S2EExecutionState* s);
   
   friend class CodeXt;
};

} // namespace plugins
} // namespace s2e

#endif
    

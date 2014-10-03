#ifndef S2E_PLUGINS_DASOS_PREPROC_CPP
#define S2E_PLUGINS_DASOS_PREPROC_CPP

extern "C" {
#include "config.h"
#include "qemu-common.h"
}

#include <s2e/S2E.h>
#include "DasosPreproc.h"
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Plugins/Opcodes.h>

extern struct CPUX86State *env;
extern s2e::S2EExecutionState *state;

namespace s2e {
namespace plugins {

//Define a plugin whose class is DasosPreproc and called "DasosPreproc".
S2E_DEFINE_PLUGIN(DasosPreproc, "Finds the beginning of shellcode in a memory segment", "DasosPreproc", "ExecutionTracer");


void DasosPreproc::initialize() {
   cfg.is_loaded = false;
   
   // Set a hook for the custom insns
   customInstructionConnection = new sigc::connection (s2e()->getCorePlugin()->onCustomInstruction.connect (sigc::mem_fun (*this, &DasosPreproc::onCustomInstruction) ) );
   return;
} // end fn initialize


bool DasosPreproc::isInShell (uint64_t pc) {
   if (pc < cfg.base_addr || pc > cfg.end_addr) {
      return false;
   }
   return true;
} // end fn isInShell


bool DasosPreproc::isPathDiff (std::vector<uint64_t> p1, std::vector<uint64_t> p2) {
   if (p1.size () != p2.size () ) {
      return true;
   }
   for (unsigned int i = 0; i < p1.size (); i++) {
      if (p1[i] != p2[i]) {
         return true;
      }
   }
   return false;
} // end fn is PathDiff


// best: needle.size () (a match at the beginning)
// average: haystack.size () - needle.size () (it must verify that no needle is within haystack)
// worst: haystack.size () (a match at the end)
bool DasosPreproc::isPathSubset (std::vector<uint64_t> needle, std::vector<uint64_t> haystack) {
   // no 1st element of needle should match 1st element of haystack otherwise they'd be the same offset, but go ahead and make this fn universal
   unsigned int j = 0;
   for (unsigned int i = 0; i < haystack.size (); i++) {
      // not a subset if the amount of needle left exceeds the amount of haystack left 
      if ((haystack.size () - i) < (needle.size () - j) ) {
         return false;
      }
      if (haystack[i] == needle[j]) {
         if (j == (needle.size () - 1) ) {
            return true;
         }
         j++;
      }
      else {
         j = 0;
      }
   }
   return false;
} // end fn isPathSubset


bool DasosPreproc::isPathUnique (std::vector<uint64_t> path) {
   if (path.size () == 0) {
      // not sure why there'd be an empty set, but don't save it as a success!
      return false;
   }
   // for each previous path, if this path is a subset of it, then return false
   for (unsigned int i = 0; i < cfg.successes.size (); i++) {
      if (isPathSubset (path, cfg.successes[i]) ) {
         return false;
      }
   }
   // if not found within forloop, then return true (this also covers is there are no previous successful paths
   return true;
} // end fn isPathUnique


void DasosPreproc::onSyscall (S2EExecutionState* state, uint64_t pc, LinuxSyscallMonitor::SyscallType sysc_type, uint32_t sysc_number, LinuxSyscallMonitor::SyscallReturnSignal& returnsignal) {
	uint64_t pid = state->getPid();
   std::ostream& stream = s2e()->getDebugStream();
   // since onSyscall isn't hooked until onCustomInstruction, this first condition should never be met
   if (!cfg.is_loaded) {
      //stream << "ignore this preload Syscall " << std::hex << sysc_number << " at addr 0x" << pc << " from pid: " << std::dec << pid << std::endl;
      return;
   }
   // if here then loaded, see if not PID
   else if (pid != cfg.proc_id) {
      //stream << "ignore this postload, non-pid Syscall " << std::hex << sysc_number << " at addr 0x" << pc << " from pid: " << std::dec << pid << std::endl;
      return;
   }
   // if here then loaded and pid matches, see if not within memory address
   else if (!isInShell (pc) ) { 
      //stream << "ignore this postload, pid, out of mem range Syscall " << std::hex << sysc_number << " at addr 0x" << pc << " from pid: " << std::dec << pid << std::endl;
      return;
   }
   
   // if here then loaded, pid matches, and within address range
   // at this point all paths result in an terminateStateEarly, so disconnect the onTranslateInstruction
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // if here we can assume that activateModule was called, so oTICS_connection was connected
   if (plgState->oTICS_connected) {
      plgState->oTICS_connection.disconnect ();
      plgState->oTICS_connected = false;
   }
   if (plgState->oTICE_connected) {
      plgState->oTICE_connection.disconnect ();
      plgState->oTICE_connected = false;
   }

   // see if not aligned to EIP
   if (pc != (cfg.eip_addr - 2) ) {
      // you shouldn't get here if you have correct offset, but if the range is invalid, then you will
      // this catches other syscalls in the monitored memory range, eg when you use an offset that follows a different execution branch
      stream << "!! Wrong syscall insn found in memory range. It's postload, pid, in range, yet not eip-2, syscall " << std::hex << sysc_number << " at addr 0x" << pc << " from pid: " << std::dec << pid << std::endl;
      //stream << "DEBUG: postload, pid, in range, unaligned syscall " << std::hex << sysc_number << " at addr 0x" << pc << " base 0x" << cfg.base_addr  << " end 0x" << cfg.end_addr << " eip-2 0x" << (cfg.eip_addr - 2) << " len " << std::dec << cfg.byte_len << " from pid " << pid << std::endl;
      s2e()->getExecutor()->terminateStateEarly (*state, "wrong syscall found in memory range");
      return;
   }
   // aligns with EIP, see if syscall not within range
   else if (sysc_number > MAX_SYSCALL_NUM) {
      stream << "!! Wrong syscall number makes no sense (>" << MAX_SYSCALL_NUM << ") " << sysc_number << ":0x" << std::hex << sysc_number << std::endl;
      s2e()->getExecutor()->terminateStateEarly (*state, "eliminated this false positive, out of range syscall number found at eip");
      return;
   }
   
   // see if cfg.sysc is not being used
   if (cfg.sysc == 1024) {
      stream << ">> Be aware that sysc is not set; is the shell read from file vs libDasosFdump struct?" << std::endl;
   }
   // see if this syscall does not match the goal syscall
   else if (sysc_number != cfg.sysc) {
      stream << "!! Not matching syscall number " << sysc_number << "!=" << cfg.sysc << std::endl;
      s2e()->getExecutor()->terminateStateEarly (*state, "eliminated this false positive, incorrect syscall number found at eip");
      return;
   }
   
   // you could enforce a minimum instruction count here like:
   // if (plgState->pcs.size() < 10) { terminateStateEarly }
   
   // All conditions to ignore are ignored, so if it's here, then it must be a positive match...
   // but is it a false positive?
   
   // we need to see if the pcs is a subset of a previous successful pcs
   if (!isPathUnique (plgState->pcs) ) {
      stream << "!! Unfortunately this execution path is a subset of a previously found success. This path has " << plgState->pcs.size () << " instructions, PCs: ";
      // print out all the PCs for each insn
      for (unsigned int i = 0; i < plgState->pcs.size (); i++) {
         stream << std::hex << plgState->pcs[i] << " ";
      }
      stream << std::endl;
      s2e()->getExecutor()->terminateStateEarly (*state, "eliminated this false positive, execution path subset of another success");
      return;
   }
   
   cfg.successes.push_back (plgState->pcs);
   stream << ">> EIP Found. Syscall number " << std::hex << sysc_number << " at addr 0x" << pc << " from pid: " << std::dec << pid << " number of instructions: " << plgState->pcs.size ();
   // print out all the PCs for each insn
   stream << "  PCs: ";
   for (unsigned int i = 0; i < plgState->pcs.size (); i++) {
      /* the following code is not right, look into it later
       * // denote if the byte was ever self modified 
      if (plgState->mem_map[plgState->pcs[i] - cfg.base_addr].size () > 1) {
         stream << "*multi-execed*:";
      }
      // compare all strings to each other and denote if any are different (eg the code self modified)
      for (unsigned int j = 0; j < plgState->mem_map[plgState->pcs[i] - cfg.base_addr].size (); j++) {
         for (unsigned int k = (j + 1); k < plgState->mem_map[plgState->pcs[i] - cfg.base_addr].size (); k++) {
            if (isPathDiff (plgState->mem_map[plgState->pcs[i] - cfg.base_addr][j], plgState->mem_map[plgState->pcs[i] - cfg.base_addr][k]) ) {
               stream << "*poly'ed*:";
            }
         }
      }*/
      stream << std::hex << plgState->pcs[i] << " ";
   }
   stream << std::endl;
   
   printMemMap (state, cfg.base_addr, cfg.byte_len);
   
   s2e()->getExecutor()->terminateStateEarly (*state, "EIP reached, success");

   return;
} // end fn onSyscall


/* Uses a custom instruction within the binary
 * must #include s2e.h in guest code source 
 * (our custom insns start around line 350 in s2e.h
 * Also must #define DASOS_PREPROC_OPCODE 0xFA line 49 in Opcodes.h
 */
void DasosPreproc::onCustomInstruction (S2EExecutionState* state, uint64_t opcode) {
   if (!OPCODE_CHECK(opcode, DASOS_PREPROC_OPCODE)) {
      return;
   }

   bool ok = true;
         
   opcode >>= 16;
   uint8_t op = opcode & 0xFF;
   opcode >>= 8;
   switch (op) {
      case 1:
         //static inline void s2e_dasospreproc_init (unsigned base, unsigned size, unsigned eip, unsigned sysc)
         // Module load
         // eax = runtime load base
         // ebx = length of memory
         // ecx = goal eip
      
         ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &(cfg.base_addr), 4);
         cfg.base_addr = cfg.base_addr & 0xffffffff;
         ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]), &(cfg.byte_len), 4);
         cfg.byte_len = cfg.byte_len & 0xffffffff;
         ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]), &(cfg.eip_addr), 4);
         cfg.eip_addr = cfg.eip_addr & 0xffffffff;
         ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EDX]), &(cfg.sysc), 4);
         cfg.sysc = cfg.sysc & 0xffffffff;
         cfg.end_addr = cfg.base_addr + cfg.byte_len;

         if (!ok) {
            s2e()->getWarningsStream (state) << "ERROR: symbolic argument was passed to s2e_op in DasosPreproc loadmodule" << std::endl;
            return;
         }
         activateModule (state);
         break;
      case 2:
         // static inline unsigned int s2e_dasospreproc_fuzz (unsigned int start, unsigned int end)
         // time to start fuzzing a particular variable
         // eax = return value
         // ebx = start of range value
         // ecx = end of range value
         uint64_t start;
         uint64_t end;
         
         ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]), &(start), 4);
         start = start & 0xffffffff;
         if (!ok) s2e()->getWarningsStream (state) << "ERROR: bad argument was passed to s2e_op: start " << start << " in DasosPreproc start fuzzing" << std::endl;
         ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]), &(end), 4);
         end = end & 0xffffffff;
         if (!ok) s2e()->getWarningsStream (state) << "ERROR: bad argument was passed to s2e_op: end " << end << " in DasosPreproc start fuzzing" << std::endl;

         if (!ok) return;
         
         if (start > end) {
            s2e()->getWarningsStream (state) << "ERROR: start (" << start << ") > end (" << end << ") is invalid range in DasosPreproc start fuzzing" << std::endl;
            return;
         }
         
         s2e()->getDebugStream () << ">> fuzzInit: datum to be iterated from " << start << " to " << end << std::endl; 

         // if there is no need to fork
         if (start == end) {
            state->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(start), 4);
            break;
         }
         // the following functions found in S2EExecutionState
         if (state->needToJumpToSymbolic () ) {
            // the state must be symbolic in order to fork
            state->jumpToSymbolic ();
         }
         // in case forking isn't enabled, enable it here
         if (!(state->isForkingEnabled () ) ) {
            state->enableForking ();
         }
         fuzzFork (state, start, end);
         break;
      case 3:
         //static inline void s2e_dasospreproc_fuzz_kill_state ()
         // end this fuzzfork
         // consider passing a message string
         //fuzzKill (state);
         break;
      case 4:
         // static inline unsigned int s2e_dasospreproc_createFork (unsigned int value)
         // return 2 states, 0 set to 0xffffffff and 1 set to value
         // eax = return value
         // ebx = value
         
         uint64_t value;
         ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]), &(value), 4);
         value = value & 0xffffffff;
         if (!ok) {
            s2e()->getWarningsStream (state) << "ERROR: bad argument was passed to s2e_op: start " << value << " in DasosPreproc start fuzzing" << std::endl;
            return;
         }
         s2e()->getDebugStream () << ">> fuzzInit: datum forking for value " << value << std::endl; 
         
         // the following functions found in S2EExecutionState
         if (state->needToJumpToSymbolic () ) {
            // the state must be symbolic in order to fork
            state->jumpToSymbolic ();
         }
         // in case forking isn't enabled, enable it here
         if (!(state->isForkingEnabled () ) ) {
            state->enableForking ();
         }
         fuzzFork1 (state, value);
         break;
      default :
         s2e()->getWarningsStream (state) << "ERROR: invalid opcode" << std::endl;
   }
   return;
} // end fn DasosPreproc::onCustomInstruction
   

void DasosPreproc::activateModule (S2EExecutionState* state) {
   if (cfg.eip_addr < cfg.base_addr || cfg.eip_addr > cfg.end_addr) {
      s2e()->getWarningsStream (state) << "ERROR: EIP 0x" << std::hex << cfg.eip_addr << " given to DasosPreproc is not within range 0x" << cfg.base_addr << "-0x" << cfg.end_addr << std::endl;
      s2e()->getExecutor()->terminateStateEarly (*state, "EIP not in range");
      return;
   }

   cfg.proc_id = (unsigned int) state->getPid();

   //onModuleLoad.emit(state);
   cfg.is_loaded = true;

   s2e()->getDebugStream() << ">> Recv'ed custom insn for a DasosPreproc memory segment within pid " << cfg.proc_id << std::hex << ", addr range: 0x" << cfg.base_addr << "-0x" << cfg.end_addr << " with eip: 0x" << cfg.eip_addr << " buffer length: " << std::dec << cfg.byte_len << " and syscall number: " << cfg.sysc << std::endl;
   
   LinuxSyscallMonitor *monitor = static_cast<LinuxSyscallMonitor*>(s2e()->getPlugin ("LinuxSyscallMonitor") );
   assert (monitor);
   monitor->getAllSyscallsSignal(state).connect (sigc::mem_fun (*this, &DasosPreproc::onSyscall) );
   
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   plgState->mem_map.resize (cfg.byte_len);
   // hook a per insn callback in here to make the cookie trail
   CorePlugin *plg = s2e()->getCorePlugin ();
   //plgState->oTICS_connection = plg->onTranslateInstructionStart.connect (sigc::mem_fun (*this, &DasosPreproc::onTranslateInstructionStart) );
   //plgState->oTICS_connected = true;
   plgState->oTICE_connection = plg->onTranslateInstructionEnd.connect (sigc::mem_fun (*this, &DasosPreproc::onTranslateInstructionEnd) );
   plgState->oTICE_connected = true;
   return;
} // end fn DasosPreproc::activateModule


void DasosPreproc::onTranslateInstructionStart (ExecutionSignal *signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   if (isInShell (pc) ) {
      // there appears to multiple calls to this per PC. Is it due to LLVM translating multiple insns per ASM insns?
      if (plgState->pcs.size () == 0 || pc != plgState->pcs.back () ) {
         // infinite loop check
         // see insn executed more than 3 times
         if (plgState->mem_map[pc - cfg.base_addr].size () > 3 ) {
            // TODO a better metric for infinite loops would be to double check that bytes for this PC have not changed
            // Also, it would be interesting to see if any bytes for any PCs within the loop have changed values (eg is this polymorphic?)
            // if we are here, then we can assume activateModule has been called, disconnect signal
            if (plgState->oTICS_connected) {
               plgState->oTICS_connection.disconnect ();
            }
            if (plgState->oTICE_connected) {
               plgState->oTICE_connection.disconnect ();
            }
            s2e()->getWarningsStream (state) << "!! Potential inifinite loop caught at 0x" << std::hex << pc << std::endl;
            s2e()->getExecutor()->terminateStateEarly (*state, "eliminated this potential infinite loop");
         }
         
         // increment the count of instructions
         //plgState->iCount++; // note that this should be the same as pcs.size()... perhaps get rid of this variable?
         // add the PC (addr) to the cookie trail
         plgState->pcs.push_back (pc);
      }
      /*if (pc == plgState->pcs.back () ) {
       s 2e()->getDebugStream() << "!!* pc == plgState->pcs.back @ 0x" << std::hex << pc << std::dec << " of len " << tb->size << "B, the 1st is 0x" << ((unsigned) (tb->tc_ptr)[0] & 0x000000ff) << std::endl;
   }*/
   }
   return;
} // end fn onTranslateInstructionStart


/* struct TranslationBlock {
 *   t arget_ulong pc;   / simulated PC corresponding to this* block (EIP + CS base) 
 *   uint16_t size;      / size of target code for this block (1 <= size <= TARGET_PAGE_SIZE) 
 *   uint16_t cflags;    / compile flags  
 *   uint8_t *tc_ptr;    / pointer to the translated code 
 */
/*
 r eturn (TranslationBlock*) readCpuStat*e(CPU_OFFSET(s2e_current_tb), 8*sizeof(void*));
 */
/* /home/s2e/s2e/dasos/s2e/./s2e/qemu/target-i386/translate.c:        
 * disas_insn (DisasContext *s, target_ulong pc_start)
 * new_pc_ptr = disas_insn (dc, pc_ptr);
 */
void DasosPreproc::onTranslateInstructionEnd (ExecutionSignal *signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   if (isInShell (pc) ) {
      // there appears to multiple calls to this per PC. Is it due to LLVM translating multiple insns per ASM insns?
      if (plgState->pcs.size () == 0 || pc != plgState->pcs.back () ) {
         // infinite loop check
         // see insn executed more than 3 times
         if (plgState->mem_map[pc - cfg.base_addr].size () > 3 ) {
            // TODO a better metric for infinite loops would be to double check that bytes for this PC have not changed
            // Also, it would be interesting to see if any bytes for any PCs within the loop have changed values (eg is this polymorphic?)
            // if we are here, then we can assume activateModule has been called, disconnect signal
            if (plgState->oTICS_connected) {
               plgState->oTICS_connection.disconnect ();
            }
            if (plgState->oTICE_connected) {
               plgState->oTICE_connection.disconnect ();
            }
            s2e()->getWarningsStream (state) << "!! Potential inifinite loop caught at 0x" << std::hex << pc << std::endl;
            s2e()->getExecutor()->terminateStateEarly (*state, "eliminated this potential infinite loop");
         }
         
         // increment the count of instructions
         //plgState->iCount++; // note that this should be the same as pcs.size()... perhaps get rid of this variable?
         // add the PC (addr) to the cookie trail
         plgState->pcs.push_back (pc);
         
         // Add the PC instance: an instance is a vector of all the insn's bytes (uint8_t/char). 
         // Since multiple instances can happen, each PC has a vector of instances.
         // There is a vector that holds each PC's set of instances
         // The mapping for this array: PC is stored at mem_map[PC - base]
         unsigned pc_instance_idx = plgState->mem_map[pc - cfg.base_addr].size (); 
         unsigned pc_instance_len = tb->lenOfLastInstr;
         // now make room for this entry
         
         /** Read value from memory, returning false if the value is symbolic */
         /* bool readMemoryConcrete(uint64_t address, void *buf, uint64_t size,
          * AddressType addressType = VirtualAddress);*/
         char pc_instance_buf[pc_instance_len];
         if (!state->readMemoryConcrete (pc, pc_instance_buf, sizeof (pc_instance_buf) ) ) {
            s2e()->getWarningsStream (state) << "ERROR: could not read guest memory @0x" << std::hex << pc << " to gather ASM insns\n";
            s2e()->getExecutor()->terminateStateEarly (*state, "eliminated a state with an invalid read");
         }
         
         plgState->mem_map[pc - cfg.base_addr].resize (pc_instance_idx + 1);
         s2e()->getDebugStream() << ">> Inserting PC Instance " << pc_instance_idx << " of len " << std::dec << pc_instance_len << "B for 0x" << std::hex << pc << ": ";
         for (unsigned j = 0; j < pc_instance_len; j++) {
            //uint8_t byte = (uint8_t) (tb->tc_ptr)[j]; // 0xff // byte at PC+j
            plgState->mem_map[pc - cfg.base_addr][pc_instance_idx].push_back (pc_instance_buf[j]);
            s2e()->getDebugStream() << " " << std::hex << ((unsigned) pc_instance_buf[j] & 0x000000ff);
         }
         s2e()->getDebugStream() << std::endl;
      }
      /*if (pc == plgState->pcs.back () ) {
       s 2e()->getDebugStream() << "!!* pc == plgState->pcs.back @ 0x" << std::hex << pc << std::dec << " of len " << tb->size << "B, the 1st is 0x" << ((unsigned) (tb->tc_ptr)[0] & 0x000000ff) << std::endl;
   }*/
   }
   return;
} // end fn onTranslateInstructionEnd




onInit {
   pushSnapshot ()
}

pushSnapshot () {
   snapshot s
   s.resize (length of input buffer)
   for (i = 0; i < s.size (); i++) {
      s[i].times_execed = 0;
   }
   mem_map.push_back (s);
}

onTransInsnEnd {
   curr_snapshot = mem_map.back ();
   insn_bytes = Read insn bytes from memory
   // check to make sure that this insn isn't diff at any bytes prev called
   // saves redoing (dec execed and then putting into new smapshot)
   beginning bytes if changed byte is in middle of insn
   foreach i 0 .. len {
      if (curr[pc + i].times_execed > 0 && curr[pc + i].byte != insn_bytes[i]){
         pushSnapshot ()
         curr_snapshot = mem_map.back ();
         End for loop
      }
   }
   //curr is the snapshot to use
   foreach i 0..len {
      if (curr[pc + i].times_execed == 0){
         curr[pc + i].byte =  insn_bytes[i]
      }
      curr[i].times_execed++;
   }
   insn i;
   i.dtackindex = memmap.size -1
   i.pc = pc
   i.len= len
   trace.push_back (i); // {memmap.size -1, pc, len});
}

Print trace
For each trace insn {
   Print insn.pc
   For each insn.len i { print memmap[insn.tackidx][insn.pc + i].byte
   If it.times_execed > 1 Mark as part of A loop
   
   Print memmap
   For each memmap snapshot
   Print snapshot
   
   Print snapshot
   Print dump as already coded using snapshot[i].byte
 
 
void DasosPreproc::printMemMap (S2EExecutionState* state, uint64_t base, unsigned len) {
    unsigned int curr_addr, end_addr, i, j;
    unsigned int min_addr = 0xffffffff;
    unsigned int max_addr = 0x00000000;
    char buf[1024];
    DECLARE_PLUGINSTATE (DasosPreprocState, state);
    
    char values[len];
    memset (values, '\0', sizeof (values) );
    /* print a visual of the order of execution
     * decided to forgo this for now since it's a repeat of the other info
     * char order[len];
    memset (order, '\0', sizeof (order) );
    for (i = 0; i < */
    
    int lastPC = -1;
    unsigned lastPC_len = 0;
    unsigned num_execed_bytes = 0;
    for (i = 0; i < len; i++) {
       if (plgState->mem_map[i].size () > 0) {
          lastPC = i;
          lastPC_len = plgState->mem_map[i][0].size (); // use 0 to keep things simple
          num_execed_bytes += plgState->mem_map[i][0].size (); // use 0 to keep things simple
          
          if ((base + i) < min_addr) {
             min_addr = (base + i);
          }
          if ((base + i + lastPC_len) > max_addr) {
             max_addr = base + i + lastPC_len;
          }
       }
       if (lastPC >= 0 && i >= (unsigned) lastPC && i < (lastPC + lastPC_len) ) {
          values[i] = plgState->mem_map[lastPC][0][i - lastPC]; // use 0 to keep things simple
       }
    }
    
    // align for print out
    curr_addr = min_addr & 0xfffffff0;
    end_addr = max_addr;
    float density = (float) num_execed_bytes / (float) (end_addr - min_addr + 1);
    s2e()->getDebugStream() << "The density (0 to 1) of this state's path is (" << std::dec << num_execed_bytes << "/" << (end_addr - min_addr + 1) << ") = " << density << std::endl;
    snprintf (buf, sizeof (buf), "Mem_map start_addr: 0x%08x, length: %uB, exec'ed bytes: %u, range: %uB, end_addr: 0x%08x\n", min_addr, len, num_execed_bytes, end_addr - min_addr + 1, end_addr);
    s2e()->getDebugStream() << buf;
    // for loop printing out dump in words with address grid like in gdb
    s2e()->getDebugStream() << "           0 1 2 3  4 5 6 7  8 9 a b  c d e f   ASCII\n";
    // for each row
    while (curr_addr < end_addr) {
       snprintf (buf, sizeof (buf), "0x%08x", curr_addr);
       s2e()->getDebugStream() << buf;
       char ascii_out[17];
       memset (ascii_out, ' ', 16);
       ascii_out[16] = '\0';
       // for each of the 4 words in the row
       for (i = 0; i < 4; i++) {
          snprintf (buf, sizeof (buf), " ");
          s2e()->getDebugStream() << buf;
          // for each of the 4 bytes in the word
          for (j = 0; j < 4; j++) {
             if (curr_addr < min_addr) {
                snprintf (buf, sizeof (buf), "  ");
                s2e()->getDebugStream() << buf;
             }
             else if (curr_addr < end_addr) {
               char tmp = values[curr_addr - base];
               if (tmp == '\0') {
                  s2e()->getDebugStream() << "--";
               }
               else {
                  snprintf (buf, sizeof (buf), "%02x", (unsigned int) tmp & 0x000000ff);
                  s2e()->getDebugStream() << buf;
               }
               ascii_out[(i * 4) + j] = isprint (tmp) ? tmp : '.';
             }
             else {
                s2e()->getDebugStream() << "  ";
             }
             curr_addr++;
          } // end for each byte
       } // end for each word
       s2e()->getDebugStream() << "  " << ascii_out << std::endl;
    } // end while each row
    s2e()->getDebugStream() << std::endl;
    
    return;
} // end fn printMemMap
 
 
 
 



void DasosPreproc::fuzzFork (S2EExecutionState* state, unsigned int start, unsigned int end) {
   /** Emulate fork via WindowsApi forkRange Code */
   unsigned int i;
   
   //assert(m_functionMonitor);
   klee::ref<klee::Expr> symb = state->createSymbolicValue (klee::Expr::Int32, "fuzz_symb");
   S2EExecutionState *curState = state;
   // by making this 1 shy of iterations you can leverage i value afterwards and the first input state so it doesn't go to waste
   for (i = start; i < end; i++) {
      //s2e()->getDebugStream () << "fuzzClone: 2 " << std::endl;
      klee::ref<klee::Expr> cond = klee::NeExpr::create (symb, klee::ConstantExpr::create (i, klee::Expr::Int32) );
      //s2e()->getDebugStream () << "fuzzClone: 3 " << std::endl;
      klee::Executor::StatePair sp = s2e()->getExecutor()->fork (*curState, cond, false);
      //s2e()->getDebugStream () << "fuzzClone: 4 " << std::endl;
      S2EExecutionState *ts = static_cast<S2EExecutionState *>(sp.first);
      S2EExecutionState *fs = static_cast<S2EExecutionState *>(sp.second);
      fs->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(i), 4); // set the return value
      curState = ts;
   }
   
   state->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(i), 4); // set the return value
   return;
} // end fn fuzzFork


void DasosPreproc::fuzzFork1 (S2EExecutionState* state, unsigned int value) {
   /** Emulate fork via WindowsApi forkRange Code */
   klee::ref<klee::Expr> symb = state->createSymbolicValue (klee::Expr::Int32, "fuzz_symb");
   klee::ref<klee::Expr> cond = klee::NeExpr::create (symb, klee::ConstantExpr::create (value, klee::Expr::Int32) );
   klee::Executor::StatePair sp = s2e()->getExecutor()->fork (*state, cond, false);
   S2EExecutionState *fs = static_cast<S2EExecutionState *>(sp.second);
   // set the return value for state 1 to given value
   fs->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(value), 4);
   // set the return value for state 0 to a canary
   value = 0xffffffff;
   state->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(value), 4);
   return;
} // end fn fuzzFork1









DasosPreprocState::DasosPreprocState () {
   //iCount = 0;
   pcs.reserve (128);
   oTICS_connected = false;
   oTICE_connected = false;
} // end fn DasosPreprocState


DasosPreprocState::DasosPreprocState (S2EExecutionState *s, Plugin *p) {
   //iCount = 0;
   pcs.reserve (128);
   oTICS_connected = false;
   oTICE_connected = false;
} // end fn DasosPreprocState


DasosPreprocState::~DasosPreprocState () {
   if (oTICS_connected) {
      oTICS_connection.disconnect ();
   }
   oTICS_connected = false;
   if (oTICE_connected) {
      oTICE_connection.disconnect ();
   }
   oTICE_connected = false;
} // end fn ~DasosPreprocState

PluginState *DasosPreprocState::clone () const {
   return new DasosPreprocState (*this);
} // end fn clone


PluginState *DasosPreprocState::factory (Plugin* p, S2EExecutionState* s) {
   return new DasosPreprocState (s, p);
} // end fn factory





} // namespace plugins
} // namespace s2e


#endif

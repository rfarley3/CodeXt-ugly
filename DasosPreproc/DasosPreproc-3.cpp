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


bool DasosPreproc::isPathSubset (std::vector<uint64_t> needle, std::vector<uint64_t> haystack) {
   // no 1st element of needle should match 1st element of haystack
   //if (needle[0] == haystack[0]) {
      // these much be the same offsets, this should happen
   //}
   // but go ahead and make it universal
   if (needle.size () == 0) {
      // not sure why there'd be an empty set, but don't save it! report it as a subset to prevent that
      return true;
   }
   unsigned int j = 0;
   for (unsigned int i = 0; i < haystack.size (); i++) {
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
   // plgState->pcs;
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
   std::ostream& stream = 	s2e()->getDebugStream();
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
   // if here we can assume that activateModule was called, so onTransInsnConnection was connected
   plgState->onTransInsnConnection.disconnect ();
   /*if (plgState->onTraceInsnConnected) {
      plgState->onTraceInsnConnection.disconnect ();
      plgState->onTraceInsnConnected = false;
   }*/
   //signal->disconnect (sigc::mem_fun (*this, &DasosPreproc::onTraceInstruction) );

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
   // if (plgState->iCount < 10) { terminateStateEarly }
   
   // All conditions to ignore are ignored, so if it's here, then it must be a positive match...
   // but is it a false positive?
   
   // we need to see if the pcs is a subset of a previous successful pcs
   if (!isPathUnique (plgState->pcs) ) {
      stream << "!! Unfortunately this execution path is a subset of a previously found success. This path has " << plgState->iCount << " instructions, PCs: ";
      // print out all the PCs for each insn
      for (unsigned int i = 0; i < plgState->pcs.size(); i++) {
         stream << std::hex << plgState->pcs[i] << " ";
      }
      stream << std::endl;
      s2e()->getExecutor()->terminateStateEarly (*state, "eliminated this false positive, execution path subset of another success");
      return;
   }
   
   cfg.successes.push_back (plgState->pcs);
   stream << ">> EIP Found. Syscall number " << std::hex << sysc_number << " at addr 0x" << pc << " from pid: " << std::dec << pid << " number of instructions: " << plgState->iCount;
   // print out all the PCs for each insn
   stream << "  PCs: ";
   for (unsigned int i = 0; i < plgState->pcs.size(); i++) {
      stream << std::hex << plgState->pcs[i] << " ";
   }
   stream << std::endl;
   
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
   // hook a per insn callback in here to make the cookie trail
   //plgState->executionTracer = static_cast<ExecutionTracer*>(s2e()->getPlugin ("ExecutionTracer") );
   //assert (plgState->m_executionTracer);
   CorePlugin *plg = s2e()->getCorePlugin ();
   plgState->onTransInsnConnection = plg->onTranslateInstructionStart.connect (sigc::mem_fun (*this, &DasosPreproc::onTranslateInstructionStart) );
   return;
} // end fn DasosPreproc::activateModule


void DasosPreproc::onTranslateInstructionStart (ExecutionSignal *signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   //if (!plgState->onTraceInsnConnected && isInShell (pc) ) {
   if (isInShell (pc) ) {
      //Connect a function that will increment the number of executed instructions.
      // this must be connected every time... otherwise it only catches 1 insn
      //plgState->onTraceInsnConnection = signal->connect (sigc::mem_fun (*this, &DasosPreproc::onTraceInstruction) );
      //plgState->onTraceInsnConnected = true;
      // there appears to multiple calls to this per PC. Is it due to LLVM translating multiple insns per ASM insns?
      if (plgState->pcs.size () == 0 || pc != plgState->pcs.back () ) {
         plgState->iCount++; // note that this should be the same as pcs.size()... perhaps get rid of this variable?
         plgState->pcs.push_back (pc);
         // TODO: insert infinite loop check
         // see if the iCount exceeds a threshold, if so then search for repeatings more than X times
      }
   }
   return;
} // end fn onTranslateInstructionStart


/*void DasosPreproc::onTraceInstruction (S2EExecutionState* state, uint64_t pc) {
   //Get the plugin state for the current path
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   
   //Increment the instruction count
   plgState->iCount++;
   plgState->pcs.push_back (pc);
   //s2e()->getDebugStream() << ">> Current insn count: " << plgState->iCount << ", pc: 0x" << std::hex << pc << std::endl;
   return;
} // end fn onTraceInstruction*/





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
   iCount = 0;
   pcs.reserve(128);
   //onTraceInsnConnected = false;
}


DasosPreprocState::DasosPreprocState (S2EExecutionState *s, Plugin *p) {
   iCount = 0;
   pcs.reserve(128);
   //onTraceInsnConnected = false;
}


DasosPreprocState::~DasosPreprocState () {}


PluginState *DasosPreprocState::clone () const {
   return new DasosPreprocState (*this);
}


PluginState *DasosPreprocState::factory (Plugin* p, S2EExecutionState* s) {
   return new DasosPreprocState (s, p);
}


} // namespace plugins
} // namespace s2e


#endif

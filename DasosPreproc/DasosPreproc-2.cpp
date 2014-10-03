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

//#include <klee/Executor.h>

extern struct CPUX86State *env;
extern s2e::S2EExecutionState *state;

namespace s2e {
namespace plugins {

//Define a plugin whose class is DasosPreproc and called "DasosPreproc".
//The plugin does not have any dependencies.
S2E_DEFINE_PLUGIN(DasosPreproc, "Finds the beginning of shellcode in a memory segment", "DasosPreproc",);

void DasosPreproc::initialize()
{
   //extern s2e::S2EExecutionState *state;
   //DECLARE_PLUGINSTATE(DasosPreprocState, state);

   cfg.is_loaded = false;
   fuzz_cfg.is_fuzzing = false;
   fuzz_cfg.orig_val = 0;
   
   // Do the hook upon first instruction:
   //firstInstructionConnection = new sigc::connection(s2e()->getCorePlugin()->onTranslateInstructionStart.connect(sigc::mem_fun(*this, &DasosPreproc::onFirstInstruction)));
   //static_cast<LinuxSyscallMonitor*>(s2e()->getPlugin("LinuxSyscallMonitor"))->LinuxSyscallMonitor::SyscallSignal.connect(sigc::mem_fun(*this, &DasosPreproc::onSyscall));
   //m_executionDetector = (ModuleExecutionDetector*)s2e()->getPlugin("ModuleExecutionDetector");
   //s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &DasosPreproc::onTranslateBlockEnd));
   customInstructionConnection = new sigc::connection (s2e()->getCorePlugin()->onCustomInstruction.connect(sigc::mem_fun(*this, &DasosPreproc::onCustomInstruction) ) );

} // end fn initialize

void DasosPreproc::onSyscall (S2EExecutionState* state, uint64_t pc, LinuxSyscallMonitor::SyscallType sysc_type, uint32_t sysc_number, LinuxSyscallMonitor::SyscallReturnSignal& returnsignal) {
   //llvm::raw_ostream &stream =   s2e()->getDebugStream();
	//stream << "Syscall number " << hexval(sysc_number) << "\n";
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
   else if (pc < cfg.base_addr || pc > cfg.end_addr) {
      //stream << "ignore this postload, pid, out of mem range Syscall " << std::hex << sysc_number << " at addr 0x" << pc << " from pid: " << std::dec << pid << std::endl;
      return;
   }
   // if here then loaded, pid matches, and within address range, see if aligned to EIP
   else if (pc != (cfg.eip_addr - 2) ) {
      // you shouldn't get here if you have correct offset, but if the range is invalid, then you will
      // this catches other syscalls in the monitored memory range, eg when you use an offset that follows a different execution branch
      stream << "!! Wrong syscall found in memory range. It's postload, pid, in range, yet not eip-2, syscall " << std::hex << sysc_number << " at addr 0x" << pc << " from pid: " << std::dec << pid << std::endl;
      //stream << "DEBUG: postload, pid, in range, unaligned syscall " << std::hex << sysc_number << " at addr 0x" << pc << " base 0x" << cfg.base_addr  << " end 0x" << cfg.end_addr << " eip-2 0x" << (cfg.eip_addr - 2) << " len " << std::dec << cfg.byte_len << " from pid " << pid << std::endl;
      s2e()->getExecutor()->terminateStateEarly (*state, "wrong syscall found in memory range");
      return;
   }
   // if here then loaded, pid matches, within address range, and aligns with EIP
   // All types to ignore are ignored, so if it's here, then it must be legit...
   stream << ">> EIP Found. Syscall number " << std::hex << sysc_number << " at addr 0x" << pc << " from pid: " << std::dec << pid;
   stream << std::endl;
   s2e()->getExecutor()->terminateStateEarly (*state, "EIP reached, success");

   return;
} // end fn onSyscall

/*
void DasosPreproc::onFirstInstruction( ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc)
{
	LinuxSyscallMonitor *monitor= static_cast<LinuxSyscallMonitor*>(s2e()->getPlugin("LinuxSyscallMonitor"));
	assert(monitor);
	monitor -> getAllSyscallsSignal(state).connect(sigc::mem_fun(*this,&DasosPreproc::onSyscall));

	if (firstInstructionConnection)
	{
		firstInstructionConnection -> disconnect();
		delete firstInstructionConnection;
		firstInstructionConnection = 0;
	}
}*/

/* Uses a custom instruction within the binary
 * static inline void s2e_dasospreproc_init (unsigned base, unsigned size, unsigned eip)
 * be sure to (within that bin's src include s2e.h, defined line 350)
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
         //static inline void s2e_dasospreproc_init (unsigned base, unsigned size, unsigned eip)
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
         cfg.end_addr = cfg.base_addr + cfg.byte_len;

         if (!ok) {
            s2e()->getWarningsStream (state)
               << "ERROR: symbolic argument was passed to s2e_op "
               "DasosPreproc loadmodule" << std::endl;
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
         
         ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]), &(fuzz_cfg.start), 4);
         fuzz_cfg.start = fuzz_cfg.start & 0xffffffff;
         if (!ok) s2e()->getWarningsStream (state) << "ERROR: bad argument was passed to s2e_op: start " << fuzz_cfg.start << " in DasosPreproc start fuzzing" << std::endl;
         ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]), &(fuzz_cfg.end), 4);
         fuzz_cfg.end = fuzz_cfg.end & 0xffffffff;
         if (!ok) s2e()->getWarningsStream (state) << "ERROR: bad argument was passed to s2e_op: end " << fuzz_cfg.end << " in DasosPreproc start fuzzing" << std::endl;

         if (!ok) return;
         
         if (fuzz_cfg.start > fuzz_cfg.end) {
            s2e()->getWarningsStream (state)
               << "ERROR: start (" << fuzz_cfg.start << ") > end (" << fuzz_cfg.end << ") is invalid range "
               "DasosPreproc start fuzzing" << std::endl;
            return;
         }
         
         s2e()->getDebugStream () 
            << ">> fuzzInit: datum to be iterated from " << fuzz_cfg.start << " to " << fuzz_cfg.end << std::endl; 

         // if there is no need to fork
         if (fuzz_cfg.start == fuzz_cfg.end) {
            state->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(fuzz_cfg.start), 4); // set the return value
            break;
         }
         fuzz_cfg.orig_state = state;
         // the following functions found in S2EExecutionState
         if (state->needToJumpToSymbolic () ) {
            // the state must be symbolic in order to fork
            state->jumpToSymbolic ();
         }
         // in case forking isn't enabled, enable it here
         if (!(state->isForkingEnabled () ) ) {
            state->enableForking ();
         }
         fuzzFork (state);
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
         
         //fuzz_cfg.orig_state = state;
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
      s2e()->getWarningsStream (state)
         << "ERROR: EIP 0x" << std::hex << cfg.eip_addr << " given to DasosPreproc is not within range 0x" << cfg.base_addr << "-0x" << cfg.end_addr << std::endl;
      s2e()->getExecutor()->terminateStateEarly (*state, "EIP not in range");
      return;
   }

   cfg.proc_id = (unsigned int) state->getPid();

   //onModuleLoad.emit(state);
   cfg.is_loaded = true;

   s2e()->getDebugStream()
      << ">> Recv'ed custom insn for a DasosPreproc memory segment within pid " << cfg.proc_id << std::hex << ", addr range: 0x" << cfg.base_addr << "-0x" << cfg.end_addr << " with eip: 0x" << cfg.eip_addr << " and buffer length: " << std::dec << cfg.byte_len << std::endl;
   
   LinuxSyscallMonitor *monitor = static_cast<LinuxSyscallMonitor*>(s2e()->getPlugin ("LinuxSyscallMonitor") );
   assert (monitor);
   monitor->getAllSyscallsSignal(state).connect (sigc::mem_fun (*this, &DasosPreproc::onSyscall) );
   
   return;
} // end fn DasosPreproc::activateModule


void DasosPreproc::fuzzFork (S2EExecutionState* state) {
   /** Emulate fork via WindowsApi forkRange Code */
   unsigned int i;
   
   //assert(m_functionMonitor);
   klee::ref<klee::Expr> symb = state->createSymbolicValue (klee::Expr::Int32, "fuzz_symb");
   S2EExecutionState *curState = state;
   // by making this 1 shy of iterations you can leverage i value afterwards and the first input state so it doesn't go to waste
   for (i = fuzz_cfg.start; i < fuzz_cfg.end; i++) {
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
   // set the return value for state 1
   fs->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(value), 4);
   // set the return value for state 0
   value = 0xffffffff;
   state->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(value), 4);
   return;
} // end fn fuzzFork1


} // namespace plugins
} // namespace s2e


#endif

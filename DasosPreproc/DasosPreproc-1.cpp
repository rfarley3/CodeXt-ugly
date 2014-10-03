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
            //state->undoCallAndJumpToSymbolic(); // causes segfault
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
         fuzzKill (state);
         break;
      default :
         s2e()->getWarningsStream (state) 
            << "Error, invalid opcode" << std::endl;
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
   //fuzz_cfg.states = (S2EExecutionState**) malloc ((fuzz_cfg.end - fuzz_cfg.start + 2) * sizeof (S2EExecutionState*) ); // be sure that there is a destructor somewhere
   klee::ref<klee::Expr> symb = state->createSymbolicValue (klee::Expr::Int32, "fuzz_symb");
   S2EExecutionState *curState = state;
   // by making this 1 shy of iterations you can leverage i value afterwards and the first input state so it doesn't go to waste
   for (i = fuzz_cfg.start; i < fuzz_cfg.end; i++) {
      //std::vector<klee::Expr> conditions; // necessary?
      //s2e()->getDebugStream () << "fuzzClone: 2 " << std::endl;
      klee::ref<klee::Expr> cond = klee::NeExpr::create (symb, klee::ConstantExpr::create (i, klee::Expr::Int32) );
      //s2e()->getDebugStream () << "fuzzClone: 3 " << std::endl;
      klee::Executor::StatePair sp = s2e()->getExecutor()->fork (*curState, cond, false);
      //s2e()->getDebugStream () << "fuzzClone: 4 " << std::endl;
      S2EExecutionState *ts = static_cast<S2EExecutionState *>(sp.first);
      S2EExecutionState *fs = static_cast<S2EExecutionState *>(sp.second);
      //fuzz_cfg.orig_state = ts;
      //fuzz_cfg.states[i] = fs;
      //fuzz_cfg.states[i]->
      //XXX: Remove this from here (but check all the callers and return a list of forked states...)
      //m_functionMonitor->eraseSp (state == fs ? ts : fs, state->getPc () );
      fs->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(i), 4); // set the return value
      curState = ts;
      //qemu: /mnt/RJFDasos/s2e/build/llvm-2.6/include/llvm/ADT/DenseMap.h:113: void llvm::DenseMap<KeyT, ValueT, KeyInfoT, ValueInfoT>::clear() [with KeyT = const llvm::BasicBlock*, ValueT = llvm::MachineBasicBlock*, KeyInfoT = llvm::DenseMapInfo<const llvm::BasicBlock*>, ValueInfoT = llvm::DenseMapInfo<llvm::MachineBasicBlock*>]: Assertion `NumEntries == 0 && "Node count imbalance!"' failed. Stack dump: 0. Running pass 'X86 DAG->DAG Instruction Selection' on function '@1
   }
   
   state->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(i), 4); // set the return value
   // mark the last one null so we can test if we've reached the end
   //fuzz_cfg.states[i] = NULL;
   
   //klee::ref<klee::Expr> cond2 = klee::EqExpr::create (symb, klee::ConstantExpr::create (1, klee::Expr::Int32) );
   //fuzz_cfg.orig_state->addConstraint (cond2);
   //s2e()->getDebugStream () << "fuzzClone: 5 " << std::endl;
   
   // state must be active when fork is called, otherwise klee fails on an assert
   //s2e()->getExecutor()->suspendState (state, true);
   //s2e()->getDebugStream () << "fuzzClone: 6 " << std::endl;
   return;
} // end fn fuzzFork


// this methodology was n' really working bc when the states were being killed (per normal) the code wouldn't continue and execute fuzzNExt
// also the state0 was never receiving its return value, this is because the code never reached the write concrete, note that you can set this per state when you fork, which would save a step
void DasosPreproc::fuzzNext (S2EExecutionState* state) {
   if (!fuzz_cfg.is_fuzzing) {
      fuzz_cfg.is_fuzzing = true;
      fuzz_cfg.pos = fuzz_cfg.start;
   }
   else {
      fuzz_cfg.pos++;
   }
   
   // if no more values to fuzz then exit, shouldn't get here
   if (fuzz_cfg.pos > fuzz_cfg.end) {
      fuzz_cfg.is_fuzzing = false;
      s2e()->getWarningsStream (fuzz_cfg.orig_state)
         << "Error: shouldn't be here: fuzzNext: no more values to use, pos: " << fuzz_cfg.pos << ", end: " << fuzz_cfg.end << std::endl; 
      
      return;
   }
      
   /*   if (fuzz_cfg.orig_state->isForkingEnabled () ) {
         fuzz_cfg.orig_state->disableForking ();
      }
      s2e()->getExecutor()->resumeState (fuzz_cfg.orig_state, true);
      fuzz_cfg.orig_state->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(fuzz_cfg.pos), 4); // set the return value
      return;
   }*/
   // else
   // fork original state again
  /* s2e()->getDebugStream ()
      << ">> fuzzNext: still more iterations @ " << fuzz_cfg.pos << std::endl;
   
   S2EExecutionState* tmp;
   if (state != NULL) {
      tmp = state;
   }
   fuzzClone ();
   if (state != NULL) {
      // this doesn't work bc the state is suspended possibly...
      s2e()->getExecutor()->terminateStateEarly (*tmp, ">> fuzzNext: told to fuzzKill curr_state just after fuzzclone");
   }
   
   // if it's the final value, then use the original state
   if (fuzz_cfg.pos == fuzz_cfg.end) {
      s2e()->getDebugStream ()
         << ">> fuzzNext: final value: " << fuzz_cfg.pos << std::endl; 
         s2e()->getExecutor()->terminateStateEarly (*(fuzz_cfg.orig_state), ">> fuzzNext: told to fuzzKill orig_state");
   }
   s2e()->getDebugStream ()
      << ">> fuzzNext: cloned state " << std::endl;
   
   s2e()->getExecutor()->resumeState (fuzz_cfg.curr_state, true);
   s2e()->getDebugStream ()
      << ">> fuzzNext: resumed curr state " << std::endl;
   fuzz_cfg.curr_state->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(fuzz_cfg.pos), 4); // set the return value*/
   return;
} // end fn fuzzNext


void DasosPreproc::fuzzClone () {
   /** Emulate fork via WindowsApi forkRange Code */
   klee::ref<klee::Expr> symb = fuzz_cfg.orig_state->createSymbolicValue (klee::Expr::Int32, "fuzz_symb");
   //std::vector<klee::Expr> conditions; // necessary?
   //s2e()->getDebugStream () << "fuzzClone: 2 " << std::endl;
   klee::ref<klee::Expr> cond = klee::NeExpr::create (symb, klee::ConstantExpr::create (0 /*fuzz_cfg.forkcall_cnt*/, klee::Expr::Int32) );
   //fuzz_cfg.forkcall_cnt++
   //s2e()->getDebugStream () << "fuzzClone: 3 " << std::endl;
   klee::Executor::StatePair sp = s2e()->getExecutor()->fork (*(fuzz_cfg.orig_state), cond, false);
   //s2e()->getDebugStream () << "fuzzClone: 4 " << std::endl;
   //S2EExecutionState *ts = static_cast<S2EExecutionState *>(sp.first);
   S2EExecutionState *fs = static_cast<S2EExecutionState *>(sp.second);
   //fuzz_cfg.orig_state = ts;
   fuzz_cfg.curr_state = fs;
   
   /*cond = klee::NeExpr::create (symb, klee::ConstantExpr::create (fuzz_cfg.forkcall_cnt, klee::Expr::Int32) );
   fuzz_cfg.forkcall_cnt++;
   sp = s2e()->getExecutor()->fork (*(fuzz_cfg.orig_state), cond, false);
   fs = static_cast<S2EExecutionState *>(sp.second);
   //fuzz_cfg.orig_state = ts;
   fuzz_cfg.next_state = fs;*/

   //klee::ref<klee::Expr> cond2 = klee::EqExpr::create (symb, klee::ConstantExpr::create (1, klee::Expr::Int32) );
   //fuzz_cfg.orig_state->addConstraint (cond2);
   //s2e()->getDebugStream () << "fuzzClone: 5 " << std::endl;
    
   // state must be active when fork is called, otherwise klee fails on an assert
   s2e()->getExecutor()->suspendState (fuzz_cfg.orig_state, true);
   s2e()->getExecutor()->suspendState (fuzz_cfg.curr_state, true);
   //s2e()->getExecutor()->suspendState (fuzz_cfg.next_state, true);
   //s2e()->getDebugStream () << "fuzzClone: 6 " << std::endl;

   return;
} // end fn fuzzClone


/* //s2e()->getExecutor()->terminateStateEarly (*(fuzz_cfg.orig_state), "devel, protection stop in DasosPreproc::fuzzNext bc code incomplete");
   // this is old code demonstrating how to write to an address in memory:
   //fuzz_cfg.orig_state->writeMemoryConcrete (*(fuzz_cfg.ptr), &(fuzz_cfg.pos), sizeof (fuzz_cfg.pos), S2EExecutionState::VirtualAddress);
   
   //void S2EExecutor::doStateFork(S2EExecutionState *originalState, const vector<S2EExecutionState*>& newStates, const vector<ref<Expr> >& newConditions) is called by:
   //S2EExecutor::StatePair S2EExecutor::fork(ExecutionState &current, ref<Expr> condition, bool isInternal) which is very similar to:
   //Executor::StatePair Executor::fork (ExecutionState &current, ref<Expr> condition, bool isInternal)
   //klee::ref<klee::Expr> cond = klee::NeExpr::create (success, klee::ConstantExpr::create (values[i], klee::Expr::Int32) );
   //klee::Executor::StatePair sp = s2e()->getExecutor()->fork (state, cond, false);
      // klee::ref<klee::Expr> condition
      // /home/s2e/s2e/dasos/s2e/./s2e/qemu/s2e/Plugins/WindowsApi/Api.cpp:    klee::ref<klee::Expr> cond = klee::SgtExpr::create(klee::ConstantExpr::create(STATUS_SUCCESS, klee::Expr::Int32), symb);
      // /home/s2e/s2e/dasos/s2e/./s2e/qemu/s2e/Plugins/WindowsApi/Api.cpp:        klee::ref<klee::Expr> cond = klee::NeExpr::create(success, klee::ConstantExpr::create(values[i], klee::Expr::Int32));
      // /home/s2e/s2e/dasos/s2e/./s2e/qemu/s2e/Plugins/WindowsApi/Api.cpp:    klee::ref<klee::Expr> cond = klee::EqExpr::create(success, klee::ConstantExpr::create(retVal, klee::Expr::Int32));
      // /home/s2e/s2e/dasos/s2e/./s2e/qemu/s2e/Plugins/WindowsApi/Api.cpp:        klee::ref<klee::Expr> cond = klee::NeExpr::create(symb, klee::ConstantExpr::create(i, klee::Expr::Int32));
      
      
    klee::ref<klee::Expr> symb = state->createSymbolicValue(klee::Expr::Int32, varName);
    klee::ref<klee::Expr> cond = klee::SgtExpr::create(klee::ConstantExpr::create(STATUS_SUCCESS, klee::Expr::Int32), symb);
    klee::Executor::StatePair sp = s2e()->getExecutor()->fork(*state, cond, false);
    
   
   klee::ref<klee::Expr> tmp_symb = (fuzz_cfg.orig_state)->createSymbolicValue (klee::Expr::Int32, "fuzzNext_tmp_symb");
   s2e()->getWarningsStream (fuzz_cfg.orig_state)
      << "fuzzNext: created symb val " << std::endl;
   s2e()->getDebugStream ()
      << "fuzzNext: created symb val " << std::endl;
      
   klee::ref<klee::Expr> tmp_cond = klee::NeExpr::create (tmp_symb, klee::ConstantExpr::create (0, klee::Expr::Int32) );
   s2e()->getWarningsStream (fuzz_cfg.orig_state)
      << "fuzzNext: created cond " << std::endl;
   s2e()->getDebugStream ()
      << "fuzzNext: created cond " << std::endl;
      
      // orig_state must not be in concrete mode
   //S2EExecutor::StatePair sp = s2e()->getExecutor()->fork (*(fuzz_cfg.orig_state), tmp_cond, false);
  //    void S2EExecutor::switchToSymbolic(S2EExecutionState *state)
      //void S2EExecutor::switchToConcrete(S2EExecutionState *state)
      //void S2EExecutor::doStateSwitch(S2EExecutionState* oldState,S2EExecutionState* newState)
   //s2e()->getExecutor()->switchToSymbolic(fuzz_cfg.orig_state);
   ObjectState *wos = state->m_cpuRegistersObject;
   memcpy(wos->getConcreteStore(true), (void*) state->m_cpuRegistersState->address, wos->size);
   state->m_runningConcrete = false;
   klee::Executor::StatePair sp = s2e()->getExecutor()->fork (*(fuzz_cfg.orig_state), tmp_cond, false);
   // S2EExecutor.cpp line 2025. S2EExecutor::StatePair sp = S2EExecutor::fork (current, condition, isInternal) is wrapper for StatePair res = Executor::fork(current, condition, isInternal) and doStateFork(static_cast<S2EExecutionState*>(&current), newStates, newConditions);
   s2e()->getWarningsStream (fuzz_cfg.orig_state)
      << "fuzzNext: forked " << std::endl;
   s2e()->getDebugStream ()
      << "fuzzNext: forked " << std::endl;
    
   S2EExecutionState* tmp = static_cast<S2EExecutionState *>(sp.first);
   fuzz_cfg.curr_state = static_cast<S2EExecutionState *>(sp.second);
   assert (tmp == fuzz_cfg.orig_state);
   
   s2e()->getWarningsStream (fuzz_cfg.orig_state)
      << "fuzzNext: next value " << fuzz_cfg.pos << std::endl;
   s2e()->getDebugStream ()
      << "fuzzNext: next value " << fuzz_cfg.pos << std::endl;
}*/


void DasosPreproc::fuzzKill (S2EExecutionState* state) {
      //s2e()->getExecutor()->terminateStateEarly (*state, "told to fuzzKill");
      //bool S2EExecutor::resumeState(S2EExecutionState *state, bool onlyAddToPtree)
      fuzzNext (state);
      return;
} // end fn fuzzKill


} // namespace plugins
} // namespace s2e


#endif

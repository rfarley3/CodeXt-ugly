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


// snapshot_idx doesn't matter directly, it's purely the pcs and byte values (which is a function of snapshot, pc, len)
/*struct insn_instance {
 u *int32_t snapshot_idx;  // which snapshot
 uint64_t pc;            // offset/pc of insn  within the snapshot (ie pc - cfg.base_addr)
 uint16_t len;           // num bytes of insn
 //Store insn byte string... Maybe? Or llvm ir decoding? Or disasm?
};*/
bool DasosPreproc::areInsn_instancesEqual (struct insn_instance i1, struct insn_instance i2, Mem_map m) {
   if (i1.pc != i2.pc) {
      return false;
   }
   if (i1.len != i2.len) {
      return false;
   }
   for (unsigned i = 0; i < i1.len; i++) {
      if (byte (&(m[i1.snapshot_idx]), i1.pc) != byte (&(m[i1.snapshot_idx]), i2.pc) ) {
         return false;
      }
   }
   return true;
} // end fn areInsn_instancesEqual


// best: needle.size () (a match at the beginning)
// average: haystack.size () - needle.size () (it must verify that no needle is within haystack)
// worst: haystack.size () (a match at the end)
bool DasosPreproc::isTraceSubset (Trace needle, Trace haystack, Mem_map m) {

   unsigned int j = 0;
   for (unsigned int i = 0; i < haystack.size (); i++) {
      // not a subset if the amount of needle left exceeds the amount of haystack left 
      if ((haystack.size () - i) < (needle.size () - j) ) {
         return false;
      }
      if (areInsn_instancesEqual (needle[j], haystack[i], m) ) {
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
} // end fn isTraceSubset


bool DasosPreproc::isTraceUnique (Trace t, Mem_map m) {
   if (t.size () == 0) {
      // not sure why there'd be an empty set, but don't save it as a success!
      return false;
   }
   // for each previous path, if this path is a subset of it, then return false
   for (unsigned int i = 0; i < cfg.successes.size (); i++) {
      if (isTraceSubset (t, cfg.successes[i].trace, m) ) {
         return false;
      }
   }
   // if not found within forloop, then return true (this also covers is there are no previous successful paths
   return true;
} // end fn isTraceUnique


void DasosPreproc::getStats (struct Snapshot* s, unsigned len) {
   s->density = (float) s->num_execed_bytes / (float) (s->max_addr - s->min_addr + 1);
   return;
} // end fn getStats


/* struct Success {
 *    Trace trace;
 *    Mem_map mem_map;
 *    float overlay_density;
 *    float avg_density;
 * }
 * success.mem_map[i] is a Snapshot
 * struct Snapshot {
 *    std::vector<struct mem_byte> mem_bytes;
 *    float density;
 *    unsigned num_execed_bytes;
 *    unsigned min_addr;
 *    unsigned max_addr;
 * };
 */
void DasosPreproc::getSuccessStats (struct Success* s) {
   s->avg_density = 0;
   for (unsigned i = 0; i < s->mem_map.size (); i++) {
      s->avg_density += s->mem_map[i].density;
   }
   s->avg_density = s->avg_density / (float) s->mem_map.size ();
   
   // TODO this needs to be the overlay of the min of all snapshot mins, the max of all snapshot maxes, and the total number of unique exec'ed bytes
   unsigned mem_map_len = s->mem_map[0].mem_bytes.size (); // to get here, there must be at least 1 snapshot, so idx 0 is safe
   unsigned overlay_min = mem_map_len;
   unsigned overlay_max = 0;
   unsigned unique_execed_bytes = 0;
   // for each PC within range
   for (unsigned i = 0; i < mem_map_len; i++) {
      bool execed = false;
      // for each snapshot determine if any execed the PC
      for (unsigned j = 0; !execed && j < s->mem_map.size (); j++) {
         if (times_execed (&(s->mem_map[j]), i ) > 0) {
            if (overlay_min > i) {
               overlay_min = i;
            }
            if (overlay_max < i) {
               overlay_max = i;
            }
            unique_execed_bytes++;
            execed = true;
         }
      }
   }
   s->overlay_density = (float) unique_execed_bytes / (float) (overlay_max - overlay_min + 1);
   return;
} // end fn getSuccessStats


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
         onActivateModule (state);
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
      case 6 :
         onFini (state);
         break;
      default :
         s2e()->getWarningsStream (state) << "ERROR: invalid opcode" << std::endl;
   }
   return;
} // end fn DasosPreproc::onCustomInstruction
   

void DasosPreproc::onActivateModule (S2EExecutionState* state) {
   if (cfg.eip_addr < cfg.base_addr || cfg.eip_addr > cfg.end_addr) {
      s2e()->getWarningsStream (state) << "ERROR: EIP 0x" << std::hex << cfg.eip_addr << " given to DasosPreproc is not within range 0x" << cfg.base_addr << "-0x" << cfg.end_addr << std::endl;
      s2e()->getExecutor()->terminateStateEarly (*state, "EIP not in range");
      return;
   }

   cfg.proc_id = (unsigned int) state->getPid();

   cfg.is_loaded = true;

   s2e()->getDebugStream() << ">> Recv'ed custom insn for a DasosPreproc memory segment within pid " << cfg.proc_id << std::hex << ", addr range: 0x" << cfg.base_addr << "-0x" << cfg.end_addr << " with eip: 0x" << cfg.eip_addr << " buffer length: " << std::dec << cfg.byte_len << " and syscall number: " << cfg.sysc << std::endl;
   
   LinuxSyscallMonitor *monitor = static_cast<LinuxSyscallMonitor*>(s2e()->getPlugin ("LinuxSyscallMonitor") );
   assert (monitor);
   monitor->getAllSyscallsSignal(state).connect (sigc::mem_fun (*this, &DasosPreproc::onSyscall) );
   
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   //plgState->mem_map.resize (cfg.byte_len);
   // hook a per insn callback in here to make the cookie trail
   CorePlugin *plg = s2e()->getCorePlugin ();
   //plgState->oTICS_connection = plg->onTranslateInstructionStart.connect (sigc::mem_fun (*this, &DasosPreproc::onTranslateInstructionStart) );
   //plgState->oTICS_connected = true;
   plgState->oTICE_connection = plg->onTranslateInstructionEnd.connect (sigc::mem_fun (*this, &DasosPreproc::onTranslateInstructionEnd) );
   plgState->oTICE_connected = true;
   return;
} // end fn DasosPreproc::onActivateModule


void DasosPreproc::onTranslateInstructionEnd (ExecutionSignal *signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   if (!isInShell (pc) ) {
      return;
   }
   
   // There are multiple calls to this fn per PC. 
   // -Could it be due to LLVM translating multiple insns per ASM insns?
   // -Could it be caused by connections not being properly disconnected in previously killed states?
   // if there is a trace and the last insn_instance has the same pc as this insn_instance, then it is duplicate, filter it out
   if (plgState->trace.size () != 0 && pc == plgState->trace.back().pc ) {
      //s2e()->getDebugStream() << "!!* pc == plgState->pcs.back @ 0x" << std::hex << pc << std::dec << " of len " << tb->size << "B, the 1st is 0x" << ((unsigned) (tb->tc_ptr)[0] & 0x000000ff) << std::endl;
      return;
   }
   
   // check if the memory map has been initialized before we try to access it
   if (plgState->mem_map.size () == 0) {
      plgState->pushSnapshot (cfg.byte_len);
   }
   struct Snapshot* s = &(plgState->mem_map.back () );
   
   // get the raw insn bytes from the guest memory
   unsigned insn_raw_len = tb->lenOfLastInstr;
   char insn_raw[insn_raw_len];
   if (!state->readMemoryConcrete (pc, insn_raw, insn_raw_len) ) {
      s2e()->getWarningsStream (state) << "ERROR: could not read guest memory @0x" << std::hex << pc << " to gather ASM insns\n";
      s2e()->getExecutor()->terminateStateEarly (*state, "eliminated a state with an invalid read");
   }
   
   // check to make sure that this insn isn't diff at any bytes prev called
   // saves peddling back on execution path
   // ie redoing beginning bytes (decrementing times_execed and then putting into new snapshot) if changed byte is in middle of insn
   bool changed = false;
   for (unsigned i = 0; !changed && i < insn_raw_len; i++) {
      // if byte at pc + i is in mem_map (has been execed at least once), then see if it matches the raw byte in guest memory at pc + i
      if (times_execed (s, pc - cfg.base_addr + i) > 0 && byte (s, pc - cfg.base_addr + i) != insn_raw[i]) {
         plgState->pushSnapshot (cfg.byte_len);
         changed = true; //i = insn_raw_len; // end forloop
      }
   }
   if (changed) { // in case the current snapshot has been changed
      s = &(plgState->mem_map.back () );
   }
   
   // at this point mem_map.back() is the proper snapshot and we have read the bytes from memory
   // do two things: 
   //   1) store the instance into the trace; and 
   //   2) store the bytes into the mem_map/snapshot
   
   //plgState->trace.push_back ({plgState->mem_map.size() - 1, pc - cfg.base_addr, insn_raw_len});
   struct insn_instance insn;
   insn.snapshot_idx = plgState->mem_map.size () - 1;
   insn.pc = pc - cfg.base_addr;
   insn.len = insn_raw_len;
   plgState->trace.push_back (insn);
   
   // write the bytes into the mem_map/snapshot
   // update any statistics as needed
   for (unsigned i = 0; i < insn_raw_len; i++) {
      unsigned pc_i = pc - cfg.base_addr + i;
      if (times_execed (s, pc_i) == 0) {
         byteWrite (s, pc_i, insn_raw[i]);
         if (pc_i < s->min_addr) {
            s->min_addr = pc_i;
         }
         if (pc_i > s->max_addr) {
            s->max_addr = pc_i;
         }
         s->num_execed_bytes++;
      }
      times_execedInc (s, pc_i);
   }
   
   // infinite loop check
   // see insn executed more than 3 times for this snapshot (no modified code anywhere within duration of past 3 executions)
   if (times_execed (s, pc - cfg.base_addr) > 3) {
      // if we are here, then we can assume activateModule has been called, disconnect signal
      if (plgState->oTICE_connected) {
         plgState->oTICE_connection.disconnect ();
      }
      s2e()->getWarningsStream (state) << "!! Potential inifinite loop caught at 0x" << std::hex << pc << std::endl;
      s2e()->getExecutor()->terminateStateEarly (*state, "eliminated this potential infinite loop");
   }
   
   //s2e()->getDebugStream() << ">> Printing PC Trace Instance ";
   //printInsn_instance (state, plgState->trace.size () - 1, false);

   return;
} // end fn onTranslateInstructionEnd


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
   /*if (plgState->oTICS_connected) {
    p lgState->oTICS*_connection.disconnect ();
    plgState->oTICS_connected = false;
}*/
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
   // if (plgState->trace.size() < 10) { terminateStateEarly }
   
   // All conditions to ignore are ignored, so if it's here, then it must be a positive match...
   // but is it a false positive?
   
   // we need to see if the trace is a subset of a previous successful pcs
   if (!isTraceUnique (plgState->trace, plgState->mem_map) ) {
      stream << "!! Unfortunately this execution path is a subset of a previously found success. This path has " << plgState->trace.size () << " instructions, PCs: ";
      // print out all the PCs for each insn
      for (unsigned int i = 0; i < plgState->trace.size (); i++) {
         stream << std::hex << (plgState->trace[i].pc + cfg.base_addr) << " ";
      }
      stream << std::endl;
      s2e()->getExecutor()->terminateStateEarly (*state, "eliminated this false positive, execution path subset of another success");
      return;
   }
   
   stream << ">> EIP Found. Syscall number " << std::hex << sysc_number << " at addr 0x" << pc << " from pid: " << std::dec << pid << " number of instructions: " << plgState->trace.size () << std::endl;
   
   // get the stats per snapshot
   for (unsigned i = 0; i < plgState->mem_map.size (); i++) {
      getStats (&(plgState->mem_map[i]), cfg.byte_len);
   }
   
   Success s;
   s.trace = plgState->trace;
   s.mem_map = plgState->mem_map;
   getSuccessStats (&s);
   printSuccess (s);
   cfg.successes.push_back (s);
   
   s2e()->getExecutor()->terminateStateEarly (*state, "EIP reached, success");
   
   return;
} // end fn onSyscall


void DasosPreproc::onFini (S2EExecutionState* state) {
   s2e()->getWarningsStream (state) << ">> Recv'ed onFini custom insn\n";
   s2e()->getDebugStream() <<  ">> Recv'ed onFini custom insn\n"
                               ">> There were " << cfg.successes.size () << " successes\n";
   float odens_max = 0;
   unsigned odens_max_idx = 0;
   float adens_max = 0;
   unsigned adens_max_idx = 0;
   for (unsigned i = 0; i < cfg.successes.size (); i++) {
      Success* s = &(cfg.successes[i]);
      if (odens_max < s->overlay_density) {
         odens_max = s->overlay_density;
         odens_max_idx = i;
      }
      if (adens_max < s->avg_density) {
         adens_max = s->avg_density;
         adens_max_idx = i;
      }
      s2e()->getDebugStream() <<  ">>    Printing success " << i << "\n";
      printSuccess (cfg.successes[i]);
      s2e()->getDebugStream() <<  ">>    Done printing success " << i << "\n";
   }
   s2e()->getDebugStream() <<  ">> Done printing succeses\n";
   s2e()->getDebugStream() <<  ">> The success/offset with the highest overlay density is " << odens_max_idx << ", value of " << odens_max << "\n";
   s2e()->getDebugStream() <<  ">> The success/offset with the highest average density is " << adens_max_idx << ", value of " << adens_max << "\n";
   //s2e()->getExecutor()->terminateStateEarly (*state, "onFini called, success");
   return;
} // end fn onFini





void DasosPreproc::printSuccess (struct Success s) {
   s2e()->getDebugStream() << ">> Success densities, overlay: " << s.overlay_density << "; avg: " << s.avg_density << "\n";
   printTrace (s.trace, s.mem_map);
   printMemMap (s.mem_map, cfg.base_addr, cfg.byte_len);
   return;
} // end fn printSuccess


/*void DasosPreproc::printTrace (S2EExecutionState* state) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   printTrace (plgState->trace, plgState->mem_map);
   return;
} // end fn printTrace*/


void DasosPreproc::printTrace (Trace t, Mem_map m) {
   s2e()->getDebugStream() << ">> Printing PC Trace (instructions in order of execution)\n";
   for (unsigned i = 0; i < t.size (); i++) {
      s2e()->getDebugStream() << ">>    ";
      printInsn_instance (t[i], m, i, true);
   }
   return;
} // end fn printTrace


/*void DasosPreproc::printInsn_instance (S2EExecutionState* state, unsigned idx, bool doDisasm) {  
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   printInsn_instance (plgState->mem_map, plgState->trace[idx], idx, doDisasm);
   return;
} // end fn printInsn_instance*/


void DasosPreproc::printInsn_instance (struct insn_instance insn, Mem_map m, unsigned idx, bool doDisasm) {
   // set the formatting of idx to be %3d so it's formatted nicely
   s2e()->getDebugStream() << std::dec << std::setw (3) << (idx + 1) << " " << std::setw(3) << insn.len << "B @0x" << std::hex << (insn.pc + cfg.base_addr) << ": ";
   uint8_t raw[insn.len];
   unsigned printed_width = 0;
   for (unsigned i = 0; i < insn.len; i++) {
      uint8_t b = byte (&(m[insn.snapshot_idx]), insn.pc + i);
      raw[i] = b;
      s2e()->getDebugStream() << " " << std::setw (2) << std::hex << ((unsigned) b & 0x000000ff);
      printed_width += 3;
      if (times_execed (&(m[insn.snapshot_idx]), insn.pc + i) > 1) {
         s2e()->getDebugStream() << "*multi-execed*";
         printed_width += 14;
      }
   }
   while (printed_width < 15) {
      s2e()->getDebugStream() << " ";
      printed_width++;
   }
   if (doDisasm) {
      printDisasm (raw, insn.len);
   }
   s2e()->getDebugStream() << std::endl;
   return;
} // end fn printInsn_instance


void DasosPreproc::printDisasm (uint8_t* raw, unsigned len) {
   //printDisasm_viaSystem (raw, len);
   printDisasm_viaLib (raw, len);
}  // end fn printDisasm


void DasosPreproc::printDisasm_viaSystem (uint8_t* raw, unsigned len) {
   char decode_cmd[256];
   char byte_str[4];
   unsigned int i;

   decode_cmd[0] = '\0';
   byte_str[0] = '\0';
   strcpy (decode_cmd, "./dasosUdcli \"");
   for (i = 0; i < len; i++) {
      sprintf (byte_str, "%02x ", ((char *) (raw + i))[0] & 0x000000ff);
      strcat (decode_cmd, byte_str);
   }
   strcat (decode_cmd, "\" 2>&1");
   //printf ("%s", decode_cmd); 
   //system (decode_cmd); // this prints to stdout, 
   // instead capture the output to a buffer
   FILE *fp;
   //int status;
   char output[1024];
   
   /* Open the command for reading. */
   fp = popen(decode_cmd, "r");
   if (fp == NULL) {
      s2e()->getDebugStream() << "Failed to run udcli\n";
      return;;
   }
   // Read the output a line at a time - output it.
   while (fgets(output, sizeof(output), fp) != NULL) {
      s2e()->getDebugStream() << output;
   }
   pclose(fp);
   return;
} // end fn printDisasm_viaSystem


// use libudis to give human readable output of ASM
void DasosPreproc::printDisasm_viaLib (uint8_t* raw, unsigned len) {
   ud_t ud_obj;
   ud_init (&ud_obj);
   ud_set_mode (&ud_obj, 32);
   ud_set_syntax (&ud_obj, UD_SYN_INTEL);
   
   ud_set_input_buffer(&ud_obj, raw, len);
   
   unsigned insn_len = 0;
   if ((insn_len = ud_disassemble (&ud_obj) ) != len) {
      s2e()->getDebugStream() << "disasm didn't do all insn bytes: " << insn_len << "/" << len << "\n";
      return;
   }
   char buf[64];
   snprintf (buf, sizeof (buf), " %-24s", ud_insn_asm (&ud_obj) );
   s2e()->getDebugStream() << buf;

   return;
} // end fn printDisasm_viaLib


/*void DasosPreproc::printMemMap (S2EExecutionState* state, uint64_t base, unsigned len) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   s2e()->getDebugStream() << ">> Printing the memory map (" << plgState->mem_map.size () << " snapshots)\n";
   for (unsigned i = 0; i < plgState->mem_map.size (); i++) {
      s2e()->getDebugStream() << ">>    Printing snapshot " << i << "\n";
      printSnapshot (state, base, len, i);
   }
   return;
} // end fn printMemMap*/


void DasosPreproc::printMemMap (Mem_map m, uint64_t base, unsigned len) {
   s2e()->getDebugStream() << ">> Printing the memory map (" << m.size () << " snapshots)\n";
   for (unsigned i = 0; i < m.size (); i++) {
      s2e()->getDebugStream() << ">>    Printing snapshot " << i << "\n";
      printSnapshot (m[i], base, len);
   }
   return;
} // end fn printMemMap


/*void DasosPreproc::printSnapshot (S2EExecutionState* state, uint64_t base, unsigned len, unsigned snapshot_idx) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   printSnapshot (plgState->mem_map[snapshot_idx], base, len);
   return;
} // end fn printSnapshot*/


void DasosPreproc::printSnapshot (struct Snapshot s, uint64_t base, unsigned len) {
   // Print dump as already coded using snapshot.mem_bytes[i].byte
   unsigned int curr_addr, end_addr, i, j;
   char buf[1024];
   
   unsigned min_addr = s.min_addr + base;
   unsigned max_addr = s.max_addr + base;
    
   // align for print out
   curr_addr = min_addr & 0xfffffff0;
   end_addr = max_addr;
   s2e()->getDebugStream() << ">>    The density (0 to 1) of this state's path is (" << std::dec << s.num_execed_bytes << "/" << (end_addr - min_addr + 1) << ") = " << s.density << std::endl;
   snprintf (buf, sizeof (buf), ">>    Mem_map start_addr: 0x%08x, length: %uB, exec'ed bytes: %u, range: %uB, end_addr: 0x%08x\n", min_addr, len, s.num_execed_bytes, end_addr - min_addr + 1, end_addr);
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
            else if (curr_addr <= end_addr) {
               if (times_execed (&s, (curr_addr - base) ) == 0) {
                  s2e()->getDebugStream() << "--";
                  ascii_out[(i * 4) + j] = '.';
               }
               else {
                  char tmp = byte (&s, (curr_addr - base) );
                  snprintf (buf, sizeof (buf), "%02x", (unsigned int) tmp & 0x000000ff);
                  s2e()->getDebugStream() << buf;
                  ascii_out[(i * 4) + j] = isprint (tmp) ? tmp : '.';
               }
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
} // end fn printSnapshot
 
 
 
 



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
   //pcs.reserve (128);
   //oTICS_connected = false;
   oTICE_connected = false;
} // end fn DasosPreprocState


DasosPreprocState::DasosPreprocState (S2EExecutionState *s, Plugin *p) {
   //iCount = 0;
   //pcs.reserve (128);
   //oTICS_connected = false;
   oTICE_connected = false;
} // end fn DasosPreprocState


void DasosPreprocState::pushSnapshot (unsigned len) {
   struct Snapshot s;
   s.mem_bytes.resize (len);
   for (unsigned i = 0; i < len; i++) {
      s.mem_bytes[i].times_execed = 0;
   }
   s.density = 0;
   s.num_execed_bytes = 0;
   s.min_addr = len;
   s.max_addr = 0;
   mem_map.push_back (s);
   return;
} // end fn pushSnapshot


/*unsigned DasosPreproc::times_execed (struct Snapshot s, uint64_t pc) {
   return times_execed (&s, pc);
} // end fn times_execed*/
/*unsigned DasosPreprocState::times_execed (struct Snapshot s, uint64_t pc) {
   return times_execed (&s, pc);
} // end fn times_execed using snapshot*/
unsigned DasosPreproc::times_execed (struct Snapshot* s, uint64_t pc) {
   if (s->mem_bytes.size () <= pc) {
      return 0;
   }
   return s->mem_bytes[pc].times_execed;
} // end fn times_execed
/*unsigned DasosPreprocState::times_execed (struct Snapshot* s, uint64_t pc) {
   if (s->mem_bytes.size () <= pc) {
      return 0;
   }
   return s->mem_bytes[pc].times_execed;
} // end fn times_execed using snapshot*/


/*unsigned DasosPreprocState::times_execed (uint64_t pc) {
   return mem_map.size () == 0 ? 0 : times_execed (pc, mem_map.size () - 1);
} // end fn times_execed


unsigned DasosPreprocState::times_execed (uint64_t pc, unsigned snapshot_idx) {
   if (mem_map.size () == 0 || snapshot_idx >= mem_map.size () ) {
      return 0;
   }
   return times_execed (mem_map[snapshot_idx], pc);
} // end fn times_execed with snapshot_idx*/


/*uint8_t DasosPreproc::byte (struct Snapshot s, uint64_t pc) {
   return byte (&s, pc);
} // end fn byte*/
uint8_t DasosPreproc::byte (struct Snapshot* s, uint64_t pc) {
   // this also checks if pc is in range
   if (times_execed (s, pc) <= 0) {
      return 0;
   }
   return s->mem_bytes[pc].byte;
} // end fn byte
/*uint8_t DasosPreprocState::byte (struct Snapshot s, uint64_t pc) {
   // this also checks if pc is in range
   if (times_execed (s, pc) <= 0) {
      return 0;
   }
   return s.mem_bytes[pc].byte;
} // end fn byte*/


/*uint8_t DasosPreprocState::byte (uint64_t pc) {
   return mem_map.size () == 0 ? 0 : byte (pc, mem_map.size () - 1);
} // end fn byte


uint8_t DasosPreprocState::byte (uint64_t pc, unsigned snapshot_idx) {
   if (mem_map.size () <= snapshot_idx) {
      return 0;
   }
   return byte (mem_map[snapshot_idx], pc);
} // end fn byte with snapshot_idx*/


void DasosPreproc::times_execedInc (struct Snapshot* s, uint64_t pc) {
   if (s->mem_bytes.size () <= pc) {
      return;
   }
   s->mem_bytes[pc].times_execed++;
   return;
} // end fn times_execedInc
/*void DasosPreprocState::times_execedInc (uint64_t pc) {
   if (mem_map.size () == 0) {
      return;
   }
   if (mem_map.back().mem_bytes.size () <= pc) {
      return;
   }
   mem_map[mem_map.size () - 1].mem_bytes[pc].times_execed++;
   return;
} // end fn times_execedInc*/


void DasosPreproc::byteWrite (struct Snapshot* s, uint64_t pc, uint8_t value) {
   if (s->mem_bytes.size () <= pc) {
      return;
   }
   s->mem_bytes[pc].byte = value;
   return;
} // end fn byteWrite
/*void DasosPreprocState::byteWrite (uint64_t pc, uint8_t value) {
   if (mem_map.size () == 0) {
      return;
   }
   if (mem_map.back().mem_bytes.size () <= pc) {
      return;
   }
   mem_map[mem_map.size () - 1].mem_bytes[pc].byte = value;
   return;
} // end fn byteWrite*/


DasosPreprocState::~DasosPreprocState () {
   /*if (oTICS_connected) {
      oTICS_connection.disconnect ();
   }
   oTICS_connected = false;*/
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
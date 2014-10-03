#ifndef S2E_PLUGINS_DASOS_PREPROC_CPP
#define S2E_PLUGINS_DASOS_PREPROC_CPP

extern "C" {
#include "config.h"
#include "qemu-common.h"
}

#include "DasosPreproc.h"
#include <s2e/S2E.h>
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
   cfg.eip_valid = false;
   cfg.sysc_valid = false;
   
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


// TODO make this use a preset vector of impossible first insn and then search it to see if the given insn exists within it
bool DasosPreproc::isInsnImpossibleFirst (uint8_t* raw_insn, unsigned raw_insn_len) {
   // the most common impossible first insn is '0 0' which is: add [eax], al
   if (raw_insn_len == 2 && raw_insn[0] == 0 && raw_insn[1] == 0) {
      return true;
   }
   return false;
} // end fn isInsnImpossibleFirst


// snapshot_idx doesn't matter directly, it's purely the pcs and byte values (which is a function of snapshot, pc, len) and snapshot is found via mem_map[snapshot_idx]
bool DasosPreproc::areInsn_instancesEqual (struct insn_instance i1, struct insn_instance i2, Mem_map m) {
   if (i1.pc != i2.pc) {
      return false;
   }
   if (i1.len != i2.len) {
      return false;
   }
   // if either is OoB, then we don't have byte values to compare, so then it is a match given all the information that we know
   if (!i1.in_range || !i2.in_range) {
      return true;
   }
   for (unsigned i = 0; i < i1.len; i++) {
      if (byte (&(m[i1.snapshot_idx]), i1.pc) != byte (&(m[i1.snapshot_idx]), i2.pc) ) {
         return false;
      }
   }
   return true;
} // end fn areInsn_instancesEqual




// is i2 immediately (physically in memory and logically of the in range insns) after i1 and are the byte values the same 
// eg part of a sled
bool DasosPreproc::isInsnRepeat (struct insn_instance i2, struct insn_instance i1, Mem_map m) {
   if ((i1.pc + i1.len) != i2.pc) {
      return false;
   }
   if (i1.len != i2.len) {
      return false;
   }
   // physically adjacent and same length
   // given the info we know it is a repeat, also prevent segfaults for OOB requests in mem map 
   if (!i1.in_range || !i2.in_range) {
      return true;
   }
   for (unsigned i = 0; i < i1.len; i++) {
      if (byte (&(m[i1.snapshot_idx]), i1.pc) != byte (&(m[i1.snapshot_idx]), i2.pc) ) {
         return false;
      }
   }
   return true;
} // end fn isInsnRepeat


// finds the next in range insn within a trace starting at index i
unsigned DasosPreproc::findNextInRange (Trace t, unsigned i) {
   while (i < t.insns.size () && !(t.insns[i].in_range) ) {
      i++;
   }
   return i;
} // end fn findNextInRange


// finds the next valid insn within a trace starting at index i
unsigned DasosPreproc::findNextValid (Trace t, unsigned i) {
   while (i < t.insns.size () && !(t.insns[i].valid) ) {
      i++;
   }
   return i;
} // end fn findNextInRange


// is needle a subset or equal to haystack
// equal is not byte for byte, it ignores OOB and invalid insns
bool DasosPreproc::isTraceSubset (Trace needle, Trace haystack, Mem_map m) {
   unsigned i = 0;
   unsigned j = 0;
   unsigned needle_first_valid = 0;
   //unsigned needle_in_range_cnt = 0;
   //unsigned haystack_in_range_cnt = 0;
   
   // do a count of all IOB, needle should be less than haystack
   //if (needle.in_range_insns > haystack.in_range_insns) {
   if (needle.valid_insns > haystack.valid_insns) {
      return false;
   }
   /*
   for (i = 0; i < haystack.insns.size (); i++) {
      if (haystack.insns[i].in_range) { haystack_in_range_cnt++; }
   }
   for (i = 0; i < needle.insns.size (); i++) {
      if (needle.insns[i].in_range) { needle_in_range_cnt++; }
   }
   if (needle_in_range_cnt > haystack_in_range_cnt) {
      return false;
   }*/

   // a trace is of a success therefore it has an EIPs, and all EIPs are IOB, therefore there must exist 1 IOB insn within both needle and haystack
   // find first IOB within each
   //s2e()->getDebugStream() << ">> !!!! 0 ("<<i<<","<<j<<")\n";
   if (!haystack.insns[i].valid) i = findNextValid (haystack, i);
   if (!needle.insns[j].valid) j = findNextValid (needle, j);
   needle_first_valid = j;
   //s2e()->getDebugStream() << ">> !!!! 1 ("<<i<<","<<j<<")\n";
   // ensure always within range and increment per haystack offset
   while (i < haystack.insns.size () && j < needle.insns.size () ) {
      //s2e()->getDebugStream() << ">> !!!! 2 ("<<i<<","<<j<<")\n";
      // if they are equal, then increment needle
      if (areInsn_instancesEqual (needle.insns[j], haystack.insns[i], m) ) {
         //s2e()->getDebugStream() << ">> !!!! 3 ("<<i<<","<<j<<")\n";
         j++;
         // if there is still needle, see if effectively the end
         if (j < needle.insns.size () && !needle.insns[j].valid) j = findNextValid (needle, j);
         // if we are out of needle, then success
         // >= to handle the case when it can not find a next valid (findNextValid would return needle.insns.size()
         if (j >= (needle.insns.size () - 1) ) {
            //s2e()->getDebugStream() << ">> !!!! 4 ("<<i<<","<<j<<")\n";
            return true;
         }
         //s2e()->getDebugStream() << ">> !!!! 5 ("<<i<<","<<j<<")\n";
      }
      else {
         j = needle_first_valid;
         //s2e()->getDebugStream() << ">> !!!! 6 ("<<i<<","<<j<<")\n";
      }
      i++;
      if (i < haystack.insns.size () && !haystack.insns[i].valid) i = findNextValid (haystack, i);
   }
   //s2e()->getDebugStream() << ">> !!!! 7\n";
   return false;
} // end fn isTraceSubset


bool DasosPreproc::isTraceUnique (Trace t, Mem_map m) {
   if (t.insns.size () == 0) {
      // not sure why there'd be an empty set, but don't save it as a success!
      return false;
   }
   // for each previous path, if this path is a subset of it, then return false
   for (unsigned int i = 0; i < cfg.successes.size (); i++) {
      if (isTraceSubset (t, cfg.successes[i].trace, m) ) {
         //cfg.successes[i].subsets.push_back (plgState->offset);
         return false;
      }
   }
   // if not found within forloop, then return true (this also covers is there are no previous successful paths
   return true;
} // end fn isTraceUnique


void DasosPreproc::getStats (struct Snapshot* s, unsigned len) {
   //s->density = (float) s->num_execed_bytes / (float) (s->max_addr - s->min_addr + 1);
   s->density = (float) s->num_valid_bytes / (float) (s->max_addr - s->min_addr + 1);
   return;
} // end fn getStats


/* success.mem_map[i] is a Snapshot
 * There are two types of densities:
 *   average: the sum of the snapshot densities divided by the number of snapshots; and,
 *   overlay: the number of unique executed bytes across all snapshots divided by the range across all snapshots 
 *            the range is the maximum PC from any snapshot minus the minimum PC in any snapshot. 
 * Average is a good inidcator of well grouped snapshots that might be spaced distantly (shellcode that jumps alot or is broken up across lots of memory); 
 * Overlay is good for shellcode which is clumped together and removes densities impacted by large jmps within the single code block.
 */
void DasosPreproc::getSuccessStats (struct Success* s) {
   s->avg_density = 0;
   for (unsigned i = 0; i < s->mem_map.size (); i++) {
      s->avg_density += s->mem_map[i].density;
   }
   s->avg_density = s->avg_density / (float) s->mem_map.size ();
   
   if (s->mem_map.size () == 0) {
      return;
   }
   unsigned mem_map_len = s->mem_map[0].mem_bytes.size (); 
   unsigned overlay_min = mem_map_len;
   unsigned overlay_max = 0;
   unsigned unique_execed_bytes = 0;
   // for each PC within range
   for (unsigned i = 0; i < mem_map_len; i++) {
      bool execed = false;
      // for each snapshot determine if any execed the PC
      for (unsigned j = 0; !execed && j < s->mem_map.size (); j++) {
         if (times_execed (&(s->mem_map[j]), i) > 0 && validated (&(s->mem_map[j]), i) ) {
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
         cfg.eip_valid = (cfg.eip_addr == EIP_UNKNOWN) ? false : true;
         ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EDX]), &(cfg.sysc), 4);
         cfg.sysc = cfg.sysc & 0xffffffff;
         cfg.sysc_valid = (cfg.sysc == SYSC_UNKNOWN) ? false : true;
         cfg.end_addr = cfg.base_addr + cfg.byte_len;
         //ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_CR3]), &(cfg.proc_cr3), 4);
         // S2EExecutionState.h: #define CPU_OFFSET(field) offsetof(CPUX86State, field)
         //cfg.proc_cr3 = cfg.proc_cr3 & 0xffffffff;

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
            s2e()->getWarningsStream (state) << "ERROR: bad argument was passed to s2e_op: start " << std::dec << value << " in DasosPreproc start fuzzing" << std::endl;
            return;
         }
         s2e()->getDebugStream () << ">> fuzzInit: datum forking for value " << std::dec << value << std::endl; 
         
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
   if (!cfg.eip_valid) {
      s2e()->getWarningsStream (state) << "Warning: EIP is not set, there may be false positives\n";
   }
   else if (cfg.eip_addr < cfg.base_addr || cfg.eip_addr > cfg.end_addr) {
      s2e()->getWarningsStream (state) << "ERROR: EIP 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << cfg.eip_addr << " given to DasosPreproc is not within range 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << cfg.base_addr << "-0x" << std::noshowbase << std::setw(8) << std::setfill('0') << cfg.end_addr << std::endl;
      terminateStateEarly_wrap (state, std::string ("EIP not in range") );
      return;
   }

   cfg.proc_id = (unsigned int) state->getPid();

   cfg.is_loaded = true;

   s2e()->getDebugStream() << ">> Recv'ed custom insn for a DasosPreproc memory segment within pid " << cfg.proc_id << std::hex << ", addr range: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << cfg.base_addr << "-0x" << std::noshowbase << std::setw(8) << std::setfill('0') << cfg.end_addr << " with eip: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << cfg.eip_addr << " buffer length: " << std::dec << cfg.byte_len << " and syscall number: " << cfg.sysc << std::endl;
   
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // hook a per insn callback in here to make the cookie trail
   CorePlugin *plg = s2e()->getCorePlugin ();
   
   /*LinuxSyscallMonitor *monitor = static_cast<LinuxSyscallMonitor*>(s2e()->getPlugin ("LinuxSyscallMonitor") );
   assert (monitor);
   monitor->getAllSyscallsSignal(state).connect (sigc::mem_fun (*this, &DasosPreproc::onSyscall_orig) );*/
   plgState->oTBE_connection = plg->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &DasosPreproc::onTranslateBlockEnd));
   plgState->oTBE_connected = true;
   
   plgState->oTICE_connection = plg->onTranslateInstructionEnd.connect (sigc::mem_fun (*this, &DasosPreproc::onTranslateInstructionEnd) );
   plgState->oTICE_connected = true;
   return;
} // end fn DasosPreproc::onActivateModule


void DasosPreproc::printOOBDebug (S2EExecutionState* state) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // get the stats per snapshot
   for (unsigned i = 0; i < plgState->mem_map.size (); i++) {
      getStats (&(plgState->mem_map[i]), cfg.byte_len);
   }
   // print the trace
   printTrace (plgState->trace, plgState->mem_map);
   printMemMap (plgState->mem_map, cfg.base_addr, cfg.byte_len);
   return;
} // end fn printOOBDebug


void DasosPreproc::validateInsn (struct insn_instance insn, uint8_t* raw, S2EExecutionState* state) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   plgState->trace.insns.push_back (insn);
   plgState->trace.in_range_insns++;
   plgState->trace.valid_insns++;
   plgState->trace.last_valid = plgState->trace.insns.size () - 1;
   
   // write the bytes into the mem_map/snapshot
   // update any statistics as needed
   for (unsigned i = 0; i < insn.len; i++) {
      unsigned pc_i = insn.pc /*- cfg.base_addr*/ + i;
      if (times_execed (&(plgState->mem_map.back () ), pc_i) == 0) {
         byteWrite (&(plgState->mem_map.back () ), pc_i, raw[i]);
         plgState->mem_map.back().num_execed_bytes++;
      }
      times_execedInc (&(plgState->mem_map.back () ), pc_i);
      
      //if (!validated (&(plgState->mem_map.back () ), pc_i) ) {
      validate (&(plgState->mem_map.back () ), pc_i);
      plgState->mem_map.back().num_valid_bytes++;
      
      if (pc_i < plgState->mem_map.back().min_addr) {
         plgState->mem_map.back().min_addr = pc_i;
      }
      if (pc_i > plgState->mem_map.back().max_addr) {
         plgState->mem_map.back().max_addr = pc_i;
      }
   }
   
   return;
} // end fn validateInsn


void DasosPreproc::invalidateInsn (unsigned idx, struct insn_instance cause, S2EExecutionState* state) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // in order to be invalidated, it must have been validated, so it must be in_range, do not mod its value
   plgState->trace.insns[idx].valid = false;
   plgState->trace.valid_insns--;
   for (unsigned i = 0; i < plgState->trace.insns[idx].len; i++) {
      invalidate (&(plgState->mem_map.back () ), plgState->trace.insns[idx].pc + i);
      plgState->mem_map.back().num_valid_bytes--;
   }
   // now handle min/max addr
   if (cause.pc < plgState->trace.insns[idx].pc) {
      plgState->mem_map.back().min_addr = cause.pc;
   }
   // NOTE this messes things up if not physically next addr higher than insns[idx]
   if (plgState->mem_map.back().min_addr == plgState->trace.insns[idx].pc && plgState->trace.insns[idx].pc < cause.pc) {
      plgState->mem_map.back().min_addr = cause.pc;
   }
   // TODO resolve max_Addr settings
   //if max_addr == 
   // NOTE assumes a repeat is logical and physical next insn, so addr min/max is greater than previous 
   return;
} // end fn invalidateInsn


void DasosPreproc::onTransKernInsns (S2EExecutionState* state, uint64_t pc) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   //s2e()->getWarningsStream (state) << "ignore this insn as it is the kernel interrupting things, but not changing the cr3 value at addr 0x" << std::hex << pc << "\n";
   plgState->kernel_insns++;
   plgState->tot_killable_insns++;
   // at some point it can go into the kernel, to another proc, and then back to the kernel (CR3 is changed to the value of another proc)
   // thus pid filtering no longer let's us catch OOB insns and our system will not kill a hung observed proc 
   if (plgState->kernel_insns > MAX_KERNEL_INSNS) {
      s2e()->getWarningsStream (state) << "ERROR: we've left our module/shellcode, within kernel now, for far too long, terminateStateEarly\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state that exec'ed out of module bounds, in the kernel, for too long") );
      return;
   }
   // otherwise just ignore this insn
   /*if (plgState->kernel_insns < 10) s2e()->getWarningsStream (state) << ",\n";
   else if (plgState->ker*nel_insns* < 100 && plgState->kernel_insns* % 10 == 0) s2e()->getWarni*ngsStream (state) << "k.\n";
   else if (plgState->kernel_insns < 1000 && plgState->kernel_insns % 100 == 0) s2e()->getWarningsStream (state) << "k;\n";
   else if (plgState->kernel_insns < 10000 && plgState->kernel_insns % 1000 == 0) s2e()->getWarningsStream (state) << "k:\n";
   else if (plgState->kernel_insns < 100000 && plgState->kernel_insns % 10000 == 0) s2e()->getWarningsStream (state) << "k!\n";
   else if (plgState->kernel_insns < 1000000 && plgState->kernel_insns % 100000 == 0) s2e()->getWarningsStream (state) << "k'\n";
   else if (plgState->kernel_insns % 1000000 == 0) s2e()->getWarningsStream (state) << "o\"\n";*/
   return;
} // end fn onTransKernInsns


// used to test if the call back is happening bc the kernel has interrupted our proccess without being called by our process
// x86 linux memory mapping puts all kernel mode code/data >= 0xc0000000
// otherwise you could look at the kernel task descriptor's state field and see if !TASK_RUNNING
bool DasosPreproc::isInKernMode (uint64_t pc) {
   if (pc >= 0xc0000000) {
      return true;
   }
   return false;
} // end fn isInKernelMode


void DasosPreproc::onTransOOBInsns (S2EExecutionState* state, uint64_t pc, TranslationBlock *tb) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // if last insn was within_range, ie it just went/jumped to OOB
   if (plgState->within_range) {
      // tell the debug about this, plgState->trace.insns.back() should be a jmp/call
      s2e()->getWarningsStream (state) << "@0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << pc << ", left buffer range after " << std::dec << plgState->in_range_insns << " IoB insns; last IoB insn @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << plgState->trace.insns.back().pc + cfg.base_addr << std::dec << ", disasm in debug.\n";
      printInsn_instance (plgState->trace.insns.back(), plgState->mem_map, plgState->trace.insns.back().snapshot_idx, true);
      // just jumped out of bounds (this is the 1st insn out of range)
      plgState->out_range_insns = 0;
      if (!plgState->expecting_jmp_OOB) {
         s2e()->getWarningsStream (state) << "ERROR: we've left our module/shellcode unexpectedly, terminateStateEarly\n";
         //printOOBDebug (state);
         terminateStateEarly_wrap (state, std::string ("eliminated a state that exec'ed out of module bounds unexpectedly") );
         return;
      }
      else /*if expecting_jmp */ /* maybe test if isInShell (pc) */ if (plgState->trace.insns.back().next_pc != pc && plgState->trace.insns.back().jmp_pc != pc) {
         s2e()->getWarningsStream (state) << "ERROR: this jump destination doesn't match what we were expecting, terminateStateEarly\n";
         //printOOBDebug (state);
         terminateStateEarly_wrap (state, std::string ("eliminated a state that is at unexpected location") );
         return;
      }
   }
   plgState->expecting_jmp_OOB = false;
   plgState->within_range = false;
   plgState->out_range_insns++;
   plgState->tot_killable_insns++;
   // if it ran more than MAX_OUT_RANGE_INSNS insns
   // then consider it "out of control" and it needs to be terminated.
   // alternatively we could use this to grow the module (observed memory range) should this insn be a legitimate write or jmp
   if (plgState->out_range_insns > MAX_OUT_RANGE_INSNS) {
      s2e()->getWarningsStream (state) << "ERROR: we've left our module/shellcode for far too long, terminateStateEarly\n";
      //printOOBDebug (state);
      terminateStateEarly_wrap (state, std::string ("eliminated a state that exec'ed out of module bounds for too long") );
      return;
   }
   
   // if it reaches here, then we want to record the OOB insn address into the trace, 
   // but not the physical bytes (since we won't be able to recall them from the mem_map later
   // ie the pc and len are stored, but the bytes values are not, also !in_range insns don't affect statistics
   struct insn_instance insn;
   insn.snapshot_idx = 0; // this doesn't really matter
   insn.pc = pc - cfg.base_addr; // note that this is relative like with in_range insns, and maybe should be an int instead of uint, or absolute
   insn.len = tb->lenOfLastInstr;
   insn.next_pc = tb->pcOfNextInstr;
   insn.in_range = false;
   insn.valid = false;
   // do not increment plgState->trace.in_range_insns
   plgState->trace.insns.push_back (insn);
   
   printOOBInsn (insn, plgState->out_range_insns, state);
   /*if (plgState->out_range_insns < 10) s2e()->getWarningsStream (state) << ",\n";
   else if* (plgState->out_range_insns < 100 && plgState->out_range_insns % 10 == 0) s2e()->getWarningsStream (state) << "o.\n";
   else if (plgState->out_range_insns < 1000 && plgState->out_range_insns % 100 == 0) s2e()->getWarningsStream (state) << "o;\n";
   else if (plgState->out_range_insns < 10000 && plgState->out_range_insns % 1000 == 0) s2e()->getWarningsStream (state) << "o:\n";
   else if (plgState->out_range_insns < 100000 && plgState->out_range_insns % 10000 == 0) s2e()->getWarningsStream (state) << "o!\n";
   else if (plgState->out_range_insns < 1000000 && plgState->out_range_insns % 100000 == 0) s2e()->getWarningsStream (state) << "o'\n";
   else if (plgState->out_range_insns % 1000000 == 0) s2e()->getWarningsStream (state) << "o\"\n";*/
   /* to debug a particular issue 5 Dec 2012 RJF
   if (plgState->out_range_insns > 20000) {
      printOOBInsn (insn, plgState->out_range_insns, state);
   }*/
   // we have all we need from it so do nothing further
   return;
} // end fn onTransOOBInsns


// given a unsigned byte, convert to a signed byte
int8_t DasosPreproc::signed1Byte (uint8_t b) {
   int8_t i = 0;
   // if negative, ie first bit is 1
   if ((b & 0x80) == 0x80) {
      // mask out 1st bit
      b = b & 0x7f;
      i = -128;
   }
   return i + b;
} // end fn signed1Byte


void DasosPreproc::onTransIOBInsns (S2EExecutionState* state, uint64_t pc, TranslationBlock *tb) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   if (!plgState->within_range) {
      // if it just entered our module, and it's entered at least once before, then note the re-entry
      if (plgState->has_entered_range) {
         s2e()->getWarningsStream (state) << "@0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << pc << ", re-entered buffer range after " << std::dec << plgState->out_range_insns << " OoB insns; last OoB insn @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << plgState->trace.insns.back().pc + cfg.base_addr << std::dec << ", disasm in debug.\n";
         printOOBInsn (plgState->trace.insns.back(), plgState->out_range_insns, state);
      }
      // back from being out of bounds
      plgState->in_range_insns = 0;
   }
   // if we've never been in the range, and we are here now, then note that this is the first time
   bool isFirstInsn = false;
   if (!plgState->has_entered_range) {
      plgState->has_entered_range = true;
      isFirstInsn = true;
      plgState->offset = pc - cfg.base_addr;
   }
   plgState->within_range = true;

   // infinite loop check
   // in an earlier version this merely checked if this PC's time_execed > 3; but that would fail on a forloop
   // this sees if we've tried to execute more than MAX_IN_RANGE insns for this instance of being within the buffer
   // see the earlier code where when the buffer is left and then returned to the cnt is reset to 0
   plgState->in_range_insns++;
   if (plgState->in_range_insns > MAX_IN_RANGE_INSNS) {
      s2e()->getWarningsStream (state) << "!! Potential inifinite loop or wandering execution exceeding MAX_IN_RANGE, caught at 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << pc << std::endl;
      terminateStateEarly_wrap (state, std::string ("eliminated this branch which exceeded MAX_IN_RANGE") );
      return;
   }

   // check if the memory map has been initialized before we try to access it
   if (plgState->mem_map.size () == 0) {
      plgState->appendSnapshot (cfg.byte_len);
   }
   
   // get the raw insn bytes from the guest memory
   unsigned insn_raw_len = tb->lenOfLastInstr;
   uint8_t insn_raw[insn_raw_len];
   if (!state->readMemoryConcrete (pc, insn_raw, insn_raw_len) ) {
      s2e()->getWarningsStream (state) << "ERROR: could not read guest memory @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << pc << " to gather ASM insns\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read") );
      return;
   }
   // this is the first insn, so see if it is an impossible first
   if (isFirstInsn && isInsnImpossibleFirst (insn_raw, insn_raw_len) ) {
      s2e()->getWarningsStream (state) << "ERROR: this is an impossible first instruction, disasm in debug\n";
      s2e()->getDebugStream() << std::setfill(' ') << std::dec << std::setw (3) << 0 << " " << std::setw(2) << insn_raw_len << "B @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << pc << ":";
      printInsn_raw (insn_raw, insn_raw_len, true);
      s2e()->getDebugStream() << std::endl;
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an impossible first instruction") );
      return;
   }
   
   // check to make sure that this insn isn't diff at any bytes prev called
   // saves peddling back on execution path
   // ie redoing beginning bytes (decrementing times_execed and then putting into new snapshot) if changed byte is in middle of insn
   // while doing the loop check for infinite loops
   //if (isInNormalizeMode (state) ) s2e()->getDebugStream() << ">> .\n"; // show a marker per insn execution
   bool changed = false;
   for (unsigned i = 0; !changed && i < insn_raw_len; i++) {
      // if byte at pc + i is in mem_map (has been execed at least once), then see if it matches the raw byte in guest memory at pc + i
      uint32_t t = times_execed (&(plgState->mem_map.back () ), pc - cfg.base_addr + i);
      // NOTE does validate need to be incorporated here?
      if (t == 0) {
         //if (isInNormalizeMode (state) ) s2e()->getDebugStream() << ">> -\n"; // show a marker per new byte execution
      }
      else { // t > 0) {
         //if (isInNormalizeMode (state) ) s2e()->getDebugStream() << ">> ^\n"; // show a marker per prev exec'ed byte execution
         uint8_t b = byte (&(plgState->mem_map.back () ), pc - cfg.base_addr + i);
         if (b != insn_raw[i]) {
            s2e()->getDebugStream() << ">> A byte at offset " << i << " has been changed, times_exec'ed before now: " << t << ", orig val: " << std::hex << b << ", new val: " << insn_raw[i] << std::dec << "\n";
            plgState->appendSnapshot (cfg.byte_len);
            changed = true; //i = insn_raw_len; // end forloop
         }
      }
   }
   
   // at this point mem_map.back() is the proper snapshot and we have read the bytes from memory
   // do two things: 
   //   1) store the instance into the trace; and 
   //   2) store the bytes into the mem_map/snapshot
   
   struct insn_instance insn;
   insn.snapshot_idx = plgState->mem_map.size () - 1;
   insn.pc = pc - cfg.base_addr;
   insn.len = insn_raw_len;
   insn.next_pc = tb->pcOfNextInstr;
   insn.jmp_pc = 0;
   insn.in_range = true;
   insn.valid = true;
   
   // I extended qemu to record the next PC, so ideally this PC should equal the last insn's next_PC
   if (plgState->pc_of_next_insn != 0 && plgState->pc_of_next_insn != 0xffffffffffffffff && plgState->pc_of_next_insn != pc) {
      s2e()->getDebugStream() << "!!* pc != prev insn's next_pc; 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " != " << std::noshowbase << std::setw(8) << std::setfill('0') << plgState->pc_of_next_insn << std::endl;
      // terminateStateEarly_wrap
   }
   plgState->pc_of_next_insn = insn.next_pc;
   // can we can leverage this to see if we're non-self?
   //plgState->pc_of_next_insn_from_last_IoB = insn.next_pc;
   if (!isInShell (insn.next_pc) ) {
      plgState->expecting_jmp_OOB = true;
   }
   
   //uint32_t conditional = 0xffffffff;
   switch (tb->s2e_tb_type) {
      case TB_JMP_IND :      // jmp/ljmp Ev, next_pc works, so no need
         insn.jmp_pc = insn.next_pc;
         break;
      case TB_JMP :            // jmp/ljmp im/Jb, loopnz, loopz, loop, jecxz, next_pc is next sequential
      case TB_COND_JMP :       // conditional jmps, next_pc is next sequential
         // find alternative jmp location: in 32b all jmp insns are 2B, 1st byte is type and 2nd is offset
         // in 64b they are 6B, 2 for type and 4 for offset
         // jmps are computed from end of insn
         // loops are jmps if ecx == 0
         insn.jmp_pc = 0xffffffff;
         if (insn.len == 2) {
            //uint8_t tval = byte (&(plgState->mem_map[insn.snapshot_idx]), insn.pc + 1);
            insn.jmp_pc = insn.pc + cfg.base_addr + insn.len + signed1Byte (insn_raw[1]); //byte (&(plgState->mem_map[insn.snapshot_idx]), insn.pc + 1) );
            //s2e()->getDebugStream() << "TB_JMP/TB_COND_JMP: pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << insn.pc + cfg.base_addr << " next_pc: 0x" << insn.next_pc << " jmp_pc: 0x" << insn.jmp_pc << " len: " << std::dec << insn.len << " offset: ";
            //char buf[1024];
            //snprintf (buf, sizeof (buf), "%d 0x%02x\n", signed1Byte (insn_raw[1]), insn_raw[1]);
            //s2e()->getDebugStream() << buf;
            //s2e()->getDebugStream() << (int) signed1Byte (insn_raw[1]) << " (0x" << std::hex << std::noshowbase << std::setw(2) << std::setfill('0') << (unsigned) insn_raw[1] << ")\n";
         }
         /*if (insn.jmp_pc != 0xffffffff) {
            s2e()->getDebugStream() << " this is a ctrl flow insn, has two possible next_pcs 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << insn.next_pc << " or 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << insn.jmp_pc  << "\n";
         }*/
         if (!isInShell (insn.jmp_pc) ) {
            plgState->expecting_jmp_OOB = true;
         }
         break;
      case TB_SYSENTER :
      case TB_SYSEXIT :
      case TB_INTERRUPT :
         /*if (insn.len == 1) { // int3 debugger code 0xcc
         }
         else*/ if (insn.len == 2) { // int N
            if (insn_raw[1] == 0x80) { //(byte (&(plgState->mem_map[insn.snapshot_idx]), insn.pc + 1) & 0xff) == 0x80) { // int 80
               // double check that pc == plgState->lastTBE_pc
               plgState->found_syscall++;// = insn.pc + cfg.base_addr;
               
               /*s2e()->getDebugStream() << " this is a syscall insn, with eax of " << std::dec << plgState->lastTBE_eax << ", or 0x" << std::hex << std::noshowbase << std::setw(3) << std::setfill('0') << plgState->lastTBE_eax << ", @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << pc << "\n";
               onSyscall (state, pc, plgState->lastTBE_eax);*/
            }
               /* for some reason the EAX isn't updated until onTranslateBlockEnd (where the LinuxSyscallMonitor/InterruptMonitor plugins are hooked at.
               // enum ESyscallType {SYSCALL_INT, SYSCALL_SYSENTER, SYSCALL_SYSCALL};
               // maybe instead of using the system call s2e module, just look here to see if it was a system call and then if so call
               if (!(state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(eax), 4 ) ) ) {
                  s2e()->getWarningsStream() << "Syscall with symbolic syscall number (EAX)!" << "\n";
               }
               else {
                  eax = eax & 0xffffffff;
                  s2e()->getDebugStream() << " this is a syscall insn, with eax of " << std::dec << eax << ", or 0x" << std::hex << std::noshowbase << std::setw(3) << std::setfill('0') << eax << ", @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << insn.pc + cfg.base_addr << "\n";
               }
               //onSyscall (state, pc, eax)*/
            //}
            // else { unknown int N
         }
         // else { unhandled TB_SYS*/INT
         break;
      // ignore the following
      case TB_DEFAULT :       // next_pc works
      case TB_COND_JMP_IND :  // this doesn't exist within i386 translate.c
      case TB_CALL :          // next_pc works
      case TB_CALL_IND :      // next_pc works
      case TB_REP :
      case TB_RET :           // next_pc doesn't work, but doesn't matter (returns 0x00000000)
         break;
   } // end switch tb_type
   
   // perhaps kill it if it doesn't jmp yet goes OOB
   /*if (plgState->expecting_jmp_OOB) {
      s2e()->getWarningsStream (state) << "@0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << pc << ", about to go out of buffer range to 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.next_pc << " or " << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.jmp_pc << "\n";
   }
   state->dumpX86State(s2e()->getDebugStream () );
   
   uint64_t t_eax;
   state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(t_eax), 4);
   t_eax = t_eax & 0xffffffff;
   s2e()->getDebugStream() << " ~~ eax " << std::dec << t_eax << ", or 0x" << std::hex << std::noshowbase << std::setw(3) << std::setfill('0') << t_eax << "\n";*/
   
   
   
   // add mechanism to detect impossible first instructions, such as '0 0'.
   // TODO reduce logic
   // if there is no last_valid_insn, add this insn
   if (plgState->trace.valid_insns == 0) {
      //s2e()->getDebugStream() << ">> !!!! Insn is the first\n";
      validateInsn (insn, insn_raw, state);
   }
   // else there are prev valid insns and if this invalidates previous
   else if (isInsnRepeat (insn, plgState->trace.insns[plgState->trace.last_valid], plgState->mem_map) ) {
      //s2e()->getDebugStream() << ">> !!!! Insn is a repeat\n";
      invalidateInsn (plgState->trace.last_valid, insn, state); //plgState->trace.insns[last_valid], state);
      validateInsn (insn, insn_raw, state);
   }
   // there are prev valid insns and this does not affect them
   else { 
      //s2e()->getDebugStream() << ">> !!!! Insn is not first and not a repeat\n";
      validateInsn (insn, insn_raw, state);
   }
   
   
   //s2e()->getDebugStream() << ">> Printing PC Trace Instance ";
   printInsn_instance (insn, plgState->mem_map, plgState->trace.insns.size () - 1, true);
   return;
} // end fn onTransIoBInsns


void DasosPreproc::onTranslateInstructionEnd (ExecutionSignal *signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // DONE Resolved, this no longer happens, but there used to be multiple calls to this fn per PC. 
   if (plgState->trace.insns.size () != 0 && pc == plgState->trace.insns.back().pc ) {
      s2e()->getDebugStream() << "!!* pc == plgState->pcs.back @ 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << std::dec << " of len " << tb->size << "B, the 1st is 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << ((unsigned) (tb->tc_ptr)[0] & 0x000000ff) << std::endl;
      return;
   }
   
   // put a test on total non-buffer insns and exit if exceeds a certain level
   if (plgState->tot_killable_insns > MAX_KILLABLE_INSNS) {
      s2e()->getWarningsStream (state) << "ERROR: too many killable insns (tot:" << plgState->tot_killable_insns << ";oob:" << plgState->out_range_insns << ";kern:" << plgState->kernel_insns << ";other:" << plgState->other_procs_insns << "), terminateStateEarly\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state that exec'ed too many killable insns, possible hang or other unexpected error") );
      return;
   }
   //if (plgState->tot_killable_insns > (MAX_KILLABLE_INSNS - 100) ) s2e()->getWarningsStream (state) << "killable:!(" << plgState->tot_killable_insns << ")\n";
   
   // handle kernel mode insns with a special case
   if (isInKernMode (pc) ) {
      // plgState->has_entered_range: if the call back is activated and has entered range once
      if (plgState->has_entered_range) {
         onTransKernInsns (state, pc);
      }
      return;
   }
   // if it's not a kernel insn, then reset the kernel_insns 
   plgState->kernel_insns = 0;
   
   // s2e's getPid() returns the higest 20b of CR3 (the TLB offset) and can be used to uniquely identify a proc
   // kernel code doesn't change the CR3 unless necessary, as it could cause unnecessary TLB flushing
   // in other words, this doesn't necessarily filter out kernel insns
   // which is why we did the isInKernMode test just a few lines up, so now the pid is valid to use
   uint64_t pid = state->getPid();
   if (pid != cfg.proc_id) {
      // plgState->has_entered_range: if the call back is activated and has entered range once
      if (plgState->has_entered_range) {
         plgState->other_procs_insns++;
         //NOTE should we not cap other procs?
         plgState->tot_killable_insns++;
         //s2e()->getWarningsStream (state) << "ignore this insn it is not from the pid we want to observe at addr 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " from pid: " << std::dec << pid << " v goal-pid: " << cfg.proc_id << "\n";
      }
      return;
   }
   plgState->other_procs_insns = 0;
   
   // NOTE on the two previous conditionals, the problem is that we want our system to allow for other procs
   // but how do we time our processing out should it hang?
   
   // at this point we are dealing with only the process we want to observe, and there are two cases: isInShell and !isInShell   
   // dont use within_range, do a hard check here
   if (!isInShell (pc) ) {
      // plgState->has_entered_range: if the call back is activated and has entered range once
      // ie if not at the code between _init/activateModule and the call to the shellcode
      if (plgState->has_entered_range) {
         // Only OOB same proc (eg library, runover-execution) insns will reach here
         onTransOOBInsns (state, pc, tb);
      }
      return;
   }
   plgState->out_range_insns = 0;
   
   // this is a legit instruction so reset the killable counter
   plgState->tot_killable_insns = 0;
   
   // at this point is NOT in kern mode, PIDs match, is IoB, regardless of has_entered_range value
   onTransIOBInsns (state, pc, tb);
   
   

   return;
} // end fn onTranslateInstructionEnd


void DasosPreproc::terminateStateEarly_wrap (S2EExecutionState* state, std::string msg) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // if here we consider that activateModule might have been called, so oTICE_connection should be disconnected
   if (plgState->oTICE_connected) {
      plgState->oTICE_connection.disconnect ();
      plgState->oTICE_connected = false;
   }
   if (plgState->oTBE_connected) {
      plgState->oTBE_connection.disconnect ();
      plgState->oTBE_connected = false;
   }
   s2e()->getExecutor()->terminateStateEarly (*state, msg.c_str () );
   return;
} // end fn terminateStateEarly_wrap


void DasosPreproc::onSyscall_orig (S2EExecutionState* state, uint64_t pc, LinuxSyscallMonitor::SyscallType sysc_type, uint32_t sysc_number, LinuxSyscallMonitor::SyscallReturnSignal& returnsignal) {
   onSyscall (state, pc, sysc_number);
   return;
} // end fn onSyscall_orig


// assumes that any system call is at the end of a block
// TBEs are signalled before TIEs
void DasosPreproc::onTranslateBlockEnd (ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc, bool, uint64_t) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   if (plgState->found_syscall) { // only set within transIOB, so this should be in range, our plugin is loaded, etc, but it's all double checked later anyways
   // the pc is going to be for the kernel... so use the last known pc
   // assumes that there is no gap in insns that could have changed eax between the insn end and the block end
   //if (cfg.is_loaded && cfg.proc_id == state->getPid () && isInShell (pc) ) {
      uint32_t eax = 0xffffffff;
      if (!(state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(eax), 4 ) ) ) {
         s2e()->getWarningsStream() << "Error: Syscall with symbolic syscall number (EAX)!" << "\n";
         terminateStateEarly_wrap (state, std::string ("Syscall with symbolic syscall number (EAX)!") );
         return;
      }
      eax = eax & 0xffffffff; // probably not needed
      //s2e()->getDebugStream() << " this is a syscall insn, with eax of " << std::dec << eax << ", or 0x" << std::hex << std::noshowbase << std::setw(3) << std::setfill('0') << eax << ", @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << pc << "\n";
      //plgState->lastTBE_pc = pc;
      //plgState->lastTBE_eax = eax;
      
      state->dumpX86State(s2e()->getDebugStream () );
      if (plgState->found_syscall > 1) {
         s2e()->getDebugStream() << "Error: found more than 1 syscall after 1st syscall was found (" << plgState->found_syscall << ")\n";
      }
      // the problem here is that upon oTIE the EAX isn't set yet
      // however, if you use the oTBE after the oTIE that catches the int 80, then the PC is for kernel space
      // even if you capture all oTBEs and use the last one at oTIE, the eax isn't set, not sure of the nuances here, but this works
      onSyscall (state, plgState->trace.insns.back().pc + cfg.base_addr, eax);
   }
   return;
} // end fn onTranslateBlockEnd


void DasosPreproc::onSyscall (S2EExecutionState* state, uint64_t pc, uint32_t sysc_number) {
   uint64_t pid = state->getPid();
   std::ostream& stream = s2e()->getDebugStream();
   // since onSyscall isn't hooked until onCustomInstruction, this first condition should never be met
   if (!cfg.is_loaded) {
      stream << "ignore this preload Syscall " << std::hex << sysc_number << " at addr 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " from pid: " << std::dec << pid << std::endl;
      return;
   }
   // if here then loaded, see if not PID
   // the kernel doesn't make system calls, so getPid () is accurate here
   else if (pid != cfg.proc_id) {
      stream << "ignore this postload, non-pid Syscall " << std::hex << sysc_number << " at addr 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " from pid: " << std::dec << pid << std::endl;
      return;
   }
   // if here then loaded and pid matches, see if not within memory address
   else if (!isInShell (pc) ) { 
      stream << "ignore this postload, pid, out of mem range Syscall " << std::hex << sysc_number << " at addr 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " from pid: " << std::dec << pid << std::endl;
      return;
   }
   
   // if here then loaded, pid matches, and within address range
   // at this point all paths result in an terminateStateEarly
   
   // Allow for when we don't know the EIP, like when reading in a raw shellcode that has not been normalized
   // if EIP is valid then see if not aligned to EIP
   // TODO make lenOfInsn dynamic (perhaps use tb->lenOfLastInstr if this hook is after the insn vs before it)
   unsigned lenOfInsn = 2; // the only possible insns to be here should be syscall cd80 or sysenter 0f34 which are only 2 bytes
   if (cfg.eip_valid && pc != (cfg.eip_addr - lenOfInsn) ) {
      // you shouldn't get here if you have correct offset, but if the range is invalid, then you will
      // this catches other syscalls in the monitored memory range, eg when you use an offset that follows a different execution branch
      stream << "!! Wrong syscall insn found in memory range. It's postload, pid, in range, yet not eip-2, syscall " << std::dec << sysc_number << "0x" << std::hex << sysc_number << " at addr 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " from pid: " << std::dec << pid << std::endl;
      //stream << "DEBUG: postload, pid, in range, unaligned syscall " << std::hex << sysc_number << " at addr 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " base 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << cfg.base_addr  << " end 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << cfg.end_addr << " eip-2 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << (cfg.eip_addr - 2) << " len " << std::dec << cfg.byte_len << " from pid " << pid << std::endl;
      terminateStateEarly_wrap (state, std::string ("wrong syscall found in memory range") );
      return;
   }
   
   // perhaps truly verify if this insn is a system call
   
   // Regardless of EIP see if syscall not within range
   if (sysc_number > MAX_SYSCALL_NUM) {
      stream << "!! Wrong syscall number makes no sense (>" << MAX_SYSCALL_NUM << ") " << sysc_number << ":0x" << std::noshowbase << std::setw(2) << std::setfill('0') << std::hex << sysc_number << std::endl;
      terminateStateEarly_wrap (state, std::string ("eliminated this false positive, out of range syscall number found at eip") );
      return;
   }
   
   // see if cfg.sysc is not being used
   if (!cfg.sysc_valid) {
      stream << ">> Be aware that sysc is not set; is the shell read from file vs libDasosFdump struct?" << std::endl;
      // all sysc_numbers will be caught so no special exceptions like if == 1 need to be made
   }
   else {
      if (cfg.sysc != 1 && sysc_number == 1) {
         stream << ">> Special exception made for syscall 1 (exit), the sysc_num was given, was not 1, but a syscall (1) was made, this may be another part of the shellcode (not the first system call)\n";
      }
      // see if this syscall does not match the goal syscall
      else if (sysc_number != cfg.sysc) {
         stream << "!! Not matching syscall number " << sysc_number << "!=" << cfg.sysc << std::endl;
         terminateStateEarly_wrap (state, std::string ("eliminated this false positive, incorrect syscall number found at eip") );
         return;
      }
   }
   
   // TODO make a semantic analysis given the sysc_number, look at the parameters and see if they match up to prototypes
   
   // you could enforce a minimum instruction count here like:
   // if (plgState->trace.insns.size() < 10) { terminateStateEarly }
   
   // All conditions to ignore are ignored, so if it's here, then it must be a positive match...
   // but is it a false positive?
   
   
   
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // we need to see if the trace is a subset of a previous successful pcs
   if (!isTraceUnique (plgState->trace, plgState->mem_map) ) {
      stream << "!! Unfortunately this execution path is a suffix/subset of a previously found success. This path has " << plgState->trace.insns.size () << " instructions, PCs: ";
      // print out all the PCs for each insn
      for (unsigned int i = 0; i < plgState->trace.insns.size (); i++) {
         if (!isInShell (plgState->trace.insns[i].pc + cfg.base_addr) ) stream << "[";
         stream << std::hex << (plgState->trace.insns[i].pc + cfg.base_addr);
         if (!isInShell (plgState->trace.insns[i].pc + cfg.base_addr) ) stream << "]";
         stream << " ";
      }
      stream << std::endl;
      terminateStateEarly_wrap (state, std::string ("eliminated this false positive, execution path subset of another success") );
      return;
   }
   
   stream << ">> EIP Found. Syscall number " << std::hex << sysc_number << " at addr 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " offset from base: " << std::dec << (pc - cfg.base_addr) << " (should be EIP-2) within pid: " << pid << " number of instructions: " << plgState->trace.insns.size () << ". This is success #" << cfg.successes.size () + 1 << "\n";
   
   // get the stats per snapshot
   for (unsigned i = 0; i < plgState->mem_map.size (); i++) {
      getStats (&(plgState->mem_map[i]), cfg.byte_len);
   }
   
   // store the success
   Success s;
   s.trace = plgState->trace;
   s.mem_map = plgState->mem_map;
   s.eip_addr = pc + lenOfInsn;
   s.offset = plgState->offset;
   getSuccessStats (&s);
   printSuccess (s);
   cfg.successes.push_back (s);
   
   // if this is state[0], then we are in normalize/preprocessor mode, so call fini/output a dump
   if (isInNormalizeMode (state) ) {
      onFiniPreproc (state);
   }
   // else
   terminateStateEarly_wrap (state, std::string ("EIP reached, success") );
   return;
} // end fn onSyscall


// if the state's id is 0, then this is the 1st state created and the one that the system uses to iterate forks
// ie in exec mode state 0 never reaches activateModule
// however in normalize mode state 0 does reach the activateModule code, thus we can use ID to determine mode
bool DasosPreproc::isInNormalizeMode (S2EExecutionState* state) {
   if (state->getID () == 0) {
      return true;
   }
   return false;
} // end fn isInNormalizeMode


void DasosPreproc::onFiniPreproc (S2EExecutionState* state) {
   s2e()->getWarningsStream (state) << ">> onFiniPreproc\n";
   s2e()->getDebugStream() <<  ">> onFiniPreproc\n";
   if (cfg.successes.size () != 1) {
      s2e()->getDebugStream() <<  "!! Error, successes is wrong size (" << cfg.successes.size () << "\n";
      terminateStateEarly_wrap (state, std::string ("onFiniPreproc successes wrong size") );
      return;
   }
   s2e()->getDebugStream() <<  ">>    Printing success " << 0 << "\n";
   printSuccess (cfg.successes[0]);
   s2e()->getDebugStream() <<  ">>    Done printing success " << 0 << "\n";
   
   terminateStateEarly_wrap (state, std::string ("EIP reached, preprocessor success") );
   return;
} // end fn onFiniPreproc


void DasosPreproc::onFini (S2EExecutionState* state) {
   s2e()->getWarningsStream (state) << ">> Recv'ed onFini custom insn\n";
   s2e()->getDebugStream() <<  ">> Recv'ed onFini custom insn\n"
                               ">> There were " << std::dec << cfg.successes.size () << " successes\n";
   float odens_max = 0;
   unsigned odens_max_idx = 0;
   float adens_max = 0;
   unsigned adens_max_idx = 0;
   std::vector<uint64_t> eips;
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
      bool exists = false;
      for (unsigned j = 0; j < eips.size (); j++) {
         if (s->eip_addr == eips[j]) {
            exists = true;
         }
      }
      if (!exists) {
         eips.push_back (s->eip_addr);
      }
      s2e()->getDebugStream() <<  ">>    Printing success " << i << "\n";
      printSuccess (cfg.successes[i]);
      s2e()->getDebugStream() <<  ">>    Done printing success " << i << "\n";
   }
   s2e()->getDebugStream() << ">> Done printing successes\n";
   s2e()->getDebugStream() << ">> The success/offset with the highest overlay density is " << odens_max_idx << ", value of " << odens_max << "\n";
   s2e()->getDebugStream() << ">> The success/offset with the highest average density is " << adens_max_idx << ", value of " << adens_max << "\n";
   s2e()->getDebugStream() << ">> There were " << eips.size () << " different eips: ";
   for (unsigned i = 0; i < eips.size (); i++) {
      s2e()->getDebugStream() << "0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << eips[i] << " ";
   }
   s2e()->getDebugStream() << "\n";
   //terminateStateEarly_wrap (*state, "onFini called, success");
   return;
} // end fn onFini





void DasosPreproc::printSuccess (struct Success s) {
   s2e()->getDebugStream() << ">> Success from offset " << s.offset << "\n";
   s2e()->getDebugStream() << ">> Success densities, overlay: " << s.overlay_density << "; avg: " << s.avg_density << "\n";
   s2e()->getDebugStream() << ">> Success eip: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << s.eip_addr << " offset from base: " << std::dec << (s.eip_addr - cfg.base_addr) <<"\n";
   printTrace (s.trace, s.mem_map);
   printMemMap (s.mem_map, cfg.base_addr, cfg.byte_len);
   return;
} // end fn printSuccess


void DasosPreproc::printTrace (Trace t, Mem_map m) {
   s2e()->getDebugStream() << ">> Printing PC Trace (instructions in order of execution)\n";
   for (unsigned i = 0; i < t.insns.size (); i++) {
      s2e()->getDebugStream() << ">>    ";
      printInsn_instance (t.insns[i], m, i, true);
   }
   return;
} // end fn printTrace


void DasosPreproc::printOOBInsn (struct insn_instance insn, unsigned idx, S2EExecutionState* state) {
   // there is no memory snapshot, this is taken directly from memory
   // get the raw insn bytes from the guest memory
   uint8_t raw[insn.len];
   // NOTE that in order to work, the original pc must have been greater in value than cfg.base_addr
   if (!state->readMemoryConcrete (insn.pc + cfg.base_addr, raw, insn.len) ) {
      s2e()->getWarningsStream (state) << "ERROR: could not read guest memory @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.pc + cfg.base_addr << " to gather ASM insns\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read") );
      return;
   }
   s2e()->getDebugStream() << std::setfill(' ') << std::dec << std::setw (3) << idx << " " << std::setw(2) << insn.len << "B @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << (insn.pc + cfg.base_addr) << ":";
   printInsn_raw (raw, insn.len, true);
   s2e()->getDebugStream() << " nextPC: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.next_pc;
   if (insn.jmp_pc != 0x00000000 && insn.jmp_pc != insn.next_pc) s2e()->getDebugStream() << " jmpPc: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.jmp_pc;
   s2e()->getDebugStream() << std::endl;
   return;
} // end fn printOOBInsn


void DasosPreproc::printInsn_raw (uint8_t* raw, unsigned raw_len, bool doDisasm) {
   unsigned printed_width = 0;
   for (unsigned i = 0; i < raw_len; i++) {
      s2e()->getDebugStream() << " ";
      printed_width += 1;
      s2e()->getDebugStream() << std::setw (2) << std::hex << ((unsigned) raw[i] & 0x000000ff);
      printed_width += 2;
   }
   while (printed_width < 18) {
      s2e()->getDebugStream() << " ";
      printed_width++;
   }
   if (doDisasm) {
      printDisasm (raw, raw_len);
   }
   return;
} // end fn printInsn_raw


void DasosPreproc::printInsn_instance (struct insn_instance insn, Mem_map m, unsigned idx, bool doDisasm) {
   s2e()->getDebugStream() << std::setfill(' ') << std::dec << std::setw (3) << (idx + 1) << " " << std::setw(2) << insn.len << "B @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << (insn.pc + cfg.base_addr) << ":";
   // if the insn was out of bounds, then we didn't capture the byte values
   if (!insn.in_range) {
      s2e()->getDebugStream() << " OOB, bytes not captured\n";
      // TODO use the PC and the symbol table to guess where it came from, for instance another internal fn or a standard library
      return;
   }
   
   uint8_t raw[insn.len];
   unsigned printed_width = 0;
   for (unsigned i = 0; i < insn.len; i++) {
      uint8_t b = byte (&(m[insn.snapshot_idx]), insn.pc + i);
      raw[i] = b;
      if (times_execed (&(m[insn.snapshot_idx]), insn.pc + i) > 1) {
         s2e()->getDebugStream() << "*";
      }
      else {
         s2e()->getDebugStream() << " ";
      }
      printed_width += 1;
      s2e()->getDebugStream() << std::setw (2) << std::hex << ((unsigned) b & 0x000000ff);
      printed_width += 2;
   }
   while (printed_width < 35) {
      s2e()->getDebugStream() << " ";
      printed_width++;
   }
   if (doDisasm) {
      printDisasm (raw, insn.len);
   }
   if (!insn.valid) {
      s2e()->getDebugStream() << "  *vestigial*";
   }
   s2e()->getDebugStream() << " nextPC: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.next_pc;
   if (insn.jmp_pc != 0x00000000 && insn.jmp_pc != insn.next_pc) s2e()->getDebugStream() << " jmpPc: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.jmp_pc;
   s2e()->getDebugStream() << std::endl;
   return;
} // end fn printInsn_instance


void DasosPreproc::printDisasm (uint8_t* raw, unsigned len) {
   printDisasmSingle (raw, len);
}  // end fn printDisasm


// use libudis to give human readable output of ASM
void DasosPreproc::printDisasmSingle (uint8_t* raw, unsigned len) {
   ud_t ud_obj;
   ud_init (&ud_obj);
   ud_set_mode (&ud_obj, 32);
   ud_set_syntax (&ud_obj, UD_SYN_INTEL);
   
   ud_set_input_buffer(&ud_obj, raw, len);
   
   unsigned insn_len = 0;
   if ((insn_len = ud_disassemble (&ud_obj) ) != len) {
      s2e()->getDebugStream() << "disasm didn't do all insn bytes: " << insn_len << "/" << len;
      return;
   }
   char buf[64];
   snprintf (buf, sizeof (buf), " %-24s", ud_insn_asm (&ud_obj) );
   s2e()->getDebugStream() << buf;

   return;
} // end fn printDisasm_viaLib


void DasosPreproc::printMemMap (Mem_map m, uint64_t base, unsigned len) {
   s2e()->getDebugStream() << ">> Printing the memory map (" << m.size () << " snapshots)\n";
   for (unsigned i = 0; i < m.size (); i++) {
      s2e()->getDebugStream() << ">>    Printing snapshot " << i << "\n";
      printSnapshot (m[i], base, len);
   }
   return;
} // end fn printMemMap


void DasosPreproc::printSnapshot (struct Snapshot s, uint64_t base, unsigned len) {
   // Print dump as already coded using snapshot.mem_bytes[i].byte
   unsigned int curr_addr, end_addr, i, j;
   char buf[1024];
   
   unsigned min_addr = s.min_addr + base;
   unsigned max_addr = s.max_addr + base;
    
   // align for print out
   curr_addr = min_addr & 0xfffffff0;
   end_addr = max_addr;
   s2e()->getDebugStream() << ">>    The density (0 to 1) of this state's path is (" << std::dec << s.num_valid_bytes << "/" << (end_addr - min_addr + 1) << ") = " << s.density << std::endl;
   snprintf (buf, sizeof (buf), ">>    Mem_map start_addr: 0x%08x, length: %uB, valid bytes: %u, exec'ed bytes: %u, range: %uB, end_addr: 0x%08x\n", min_addr, len, s.num_valid_bytes, s.num_execed_bytes, end_addr - min_addr + 1, end_addr);
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
               if (times_execed (&s, (curr_addr - base) ) == 0 || !validated (&s, (curr_addr - base) ) ) {
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
 
 
unsigned DasosPreproc::times_execed (struct Snapshot* s, uint64_t pc) {
   if (s->mem_bytes.size () <= pc) {
      return 0;
   }
   return s->mem_bytes[pc].times_execed;
} // end fn times_execed


uint8_t DasosPreproc::byte (struct Snapshot* s, uint64_t pc) {
   // this also checks if pc is in range
   if (times_execed (s, pc) <= 0) {
      return 0;
   }
   return s->mem_bytes[pc].byte;
} // end fn byte


bool DasosPreproc::validated (struct Snapshot* s, uint64_t pc) {
   if (s->mem_bytes.size () <= pc) {
      return false;
   }
   return s->mem_bytes[pc].validated;
} // end fn validated


void DasosPreproc::times_execedInc (struct Snapshot* s, uint64_t pc) {
   if (s->mem_bytes.size () <= pc) {
      return;
   }
   s->mem_bytes[pc].times_execed++;
   return;
} // end fn times_execedInc


void DasosPreproc::byteWrite (struct Snapshot* s, uint64_t pc, uint8_t value) {
   if (s->mem_bytes.size () <= pc) {
      return;
   }
   s->mem_bytes[pc].byte = value;
   return;
} // end fn byteWrite 


void DasosPreproc::validate (struct Snapshot* s, uint64_t pc) {
   if (s->mem_bytes.size () <= pc) {
      return;
   }
   s->mem_bytes[pc].validated = true;
   return;
} // end fn validated


void DasosPreproc::invalidate (struct Snapshot* s, uint64_t pc) {
   if (s->mem_bytes.size () <= pc) {
      return;
   }
   s->mem_bytes[pc].validated = false;
   return;
} // end fn invalidated
 
 






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
   //DECLARE_PLUGINSTATE (DasosPreprocState, state);
   //plgState->offset = value & 0xffffffff;
   // set the return value for state 0 to a canary
   value = 0xffffffff;
   state->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(value), 4);
   return;
} // end fn fuzzFork1






DasosPreprocState::DasosPreprocState () {
   oTICE_connected = false;
   oTBE_connected = false;
   has_entered_range = false;
   within_range = false;
   in_range_insns = 0;
   out_range_insns = 0;
   other_procs_insns = 0;
   tot_killable_insns = 0;
   trace.in_range_insns = 0;
   trace.valid_insns = 0;
   kernel_insns = 0;
   pc_of_next_insn_from_last_IoB = 0;
   pc_of_next_insn = 0;
   expecting_jmp_OOB = false;
   found_syscall = 0;
} // end fn DasosPreprocState


DasosPreprocState::DasosPreprocState (S2EExecutionState *s, Plugin *p) {
   oTICE_connected = false;
   oTBE_connected = false;
   has_entered_range = false;
   within_range = false;
   in_range_insns = 0;
   out_range_insns = 0;
   other_procs_insns = 0;
   tot_killable_insns = 0;
   trace.in_range_insns = 0;
   trace.valid_insns = 0;
   kernel_insns = 0;
   pc_of_next_insn_from_last_IoB = 0;
   pc_of_next_insn = 0;
   expecting_jmp_OOB = false;
   found_syscall = 0;
} // end fn DasosPreprocState


void DasosPreprocState::appendSnapshot (unsigned len) {
   struct Snapshot s;
   s.mem_bytes.resize (len);
   for (unsigned i = 0; i < len; i++) {
      s.mem_bytes[i].times_execed = 0;
      s.mem_bytes[i].validated = false;
   }
   s.density = 0;
   s.num_execed_bytes = 0;
   s.num_valid_bytes = 0;
   s.min_addr = len;
   s.max_addr = 0;
   mem_map.push_back (s);
   return;
} // end fn appendSnapshot


DasosPreprocState::~DasosPreprocState () {
   if (oTICE_connected) {
      oTICE_connection.disconnect ();
   }
   oTICE_connected = false;
   if (oTBE_connected) {
      oTBE_connection.disconnect ();
   }
   oTBE_connected = false;
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

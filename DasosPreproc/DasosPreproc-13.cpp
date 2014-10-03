#ifndef S2E_PLUGINS_DASOS_PREPROC_CPP
#define S2E_PLUGINS_DASOS_PREPROC_CPP

extern "C" {
#include "config.h"
#include "qemu-common.h"
extern struct CPUX86State* env;
}

#include "DasosPreproc.h"
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Plugins/Opcodes.h>

extern struct CPUX86State* env;
extern s2e::S2EExecutionState* state;

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


// snapshot_idx doesn't matter directly, it's purely the pcs and byte values (which is a function of snapshot, pc, len) and snapshot is found via code_map[snapshot_idx]
bool DasosPreproc::areInsnInstancesEqual (exec_instance i1, exec_instance i2) { //, Mem_map m) {
   if (i1.addr != i2.addr) {
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
      //if (byte (m[i1.snapshot_idx], i1.addr) != byte (m[i1.snapshot_idx], i2.addr) ) {
      if (i1.bytes[i].byte != i2.bytes[i].byte) {
         return false;
      }
   }
   return true;
} // end fn areInsnInstancesEqual



/*
// is i2 immediately (physically in memory and logically of the in range insns) after i1 and are the byte values the same 
// eg part of a sled
bool DasosPreproc::isInsnRepeat (trans_instance i2, trans_instance i1, Mem_map m) {
   if ((i1.addr + i1.len) != i2.addr) {
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
      if (byte (m[i1.snapshot_idx], i1.addr) != byte (m[i1.snapshot_idx], i2.addr) ) {
         return false;
      }
   }
   return true;
} // end fn isInsnRepeat*/


/*
// finds the next in range insn within a trans_trace starting at index i
unsigned DasosPreproc::findNextInRange (Trans_Trace t, unsigned i) {
   while (i < t.insns.size () && !(t.insns[i].in_range) ) {
      i++;
   }
   return i;
} // end fn findNextInRange*/


// finds the next valid insn within a trans_trace starting at index i
unsigned DasosPreproc::findNextValid (Exec_Trace t, unsigned i) {
   while (i < t.insns.size () && !(t.insns[i].valid) ) {
      i++;
   }
   return i;
} // end fn findNextValid


// is needle a subset or equal to haystack
// equal is not byte for byte, it ignores OOB and invalid insns
bool DasosPreproc::isInsnTraceSubset (Exec_Trace needle, Exec_Trace haystack) { //, Mem_map m) {
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

   // a trans_trace is of a success therefore it has an EIPs, and all EIPs are IOB, therefore there must exist 1 IOB insn within both needle and haystack
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
      if (areInsnInstancesEqual (needle.insns[j], haystack.insns[i]) ) { //, m) ) {
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
} // end fn isInsnTraceSubset


bool DasosPreproc::isInsnTraceUnique (Exec_Trace t, std::vector<Success> s) { //, Mem_map m) {
   if (t.insns.size () == 0) {
      // not sure why there'd be an empty set, but don't save it as a success!
      return false;
   }
   // for each previous path, if this path is a subset of it, then return false
   for (unsigned int i = 0; i < s.size (); i++) {
      if (isInsnTraceSubset (t, s[i].exec_trace) ) { //, m) ) {
         //cfg.successes[i].subsets.push_back (plgState->offset);
         return false;
      }
   }
   // if not found within forloop, then return true (this also covers is there are no previous successful paths
   return true;
} // end fn isInsnTraceUnique


/*void DasosPreproc::getStats (Snapshot& s, unsigned len) {
   //s->density = (float) s->num_used_bytes / (float) (s->max_addr - s->min_addr + 1);
   s.density = (float) s.num_valid_bytes / (float) (s.max_addr - s.min_addr + 1);
   return;
} // end fn getStats*/


/* success.code_map[i] is a Snapshot
 *  There are two types of densities:
 *   average: the sum of the snapshot densities divided by the number of snapshots; and,
 *   overlay: the number of unique executed bytes across all snapshots divided by the range across all snapshots 
 *            the range is the maximum PC from any snapshot minus the minimum PC in any snapshot. 
 * Average is a good inidcator of well grouped snapshots that might be spaced distantly (shellcode that jumps alot or is broken up across lots of memory); 
 * Overlay is good for shellcode which is clumped together and removes densities impacted by large jmps within the single code block.
 */
void DasosPreproc::getSuccessStats (Success& s) {
   s.avg_density = 0;
   for (unsigned i = 0; i < s.code_map.size (); i++) {
      s.avg_density += s.code_map[i].density;
   }
   s.avg_density = s.avg_density / (float) s.code_map.size ();
   
   if (s.code_map.size () == 0) {
      return;
   }
   unsigned code_map_len = s.code_map[0].mem_bytes.size (); 
   unsigned overlay_min = code_map_len;
   unsigned overlay_max = 0;
   unsigned unique_used_bytes = 0;
   // for each PC within range
   for (unsigned i = 0; i < code_map_len; i++) {
      bool used = false;
      // for each snapshot determine if any used the PC
      for (unsigned j = 0; !used && j < s.code_map.size (); j++) {
         if (timesUsed (s.code_map[j], i) > 0 && validated (s.code_map[j], i) ) {
            if (overlay_min > i) {
               overlay_min = i;
            }
            if (overlay_max < i) {
               overlay_max = i;
            }
            unique_used_bytes++;
            used = true;
         }
      }
   }
   s.overlay_density = (float) unique_used_bytes / (float) (overlay_max - overlay_min + 1);
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
      terminateStateEarly_wrap (state, std::string ("EIP not in range"), false);
      return;
   }

   cfg.proc_id = (unsigned int) state->getPid();

   cfg.is_loaded = true;
   

   s2e()->getDebugStream() << ">> Recv'ed custom insn for a DasosPreproc memory segment within pid " << cfg.proc_id << std::hex << ", addr range: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << cfg.base_addr << "-0x" << std::noshowbase << std::setw(8) << std::setfill('0') << cfg.end_addr << " with eip: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << cfg.eip_addr << " buffer length: " << std::dec << cfg.byte_len << " and syscall number: " << cfg.sysc << std::endl;
   
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // hook a per insn callback in here to make the cookie trail
   CorePlugin* plg = s2e()->getCorePlugin ();
   
   plgState->oDMA_connection = plg->onDataMemoryAccess.connect (sigc::mem_fun(*this, &DasosPreproc::onDataMemoryAccess) );
   plgState->oDMA_connected = true;
   
   /*LinuxSyscallMonitor* monitor = static_cast<LinuxSyscallMonitor*>(s2e()->getPlugin ("LinuxSyscallMonitor") );
   assert (monitor);
   monitor->getAllSyscallsSignal(state).connect (sigc::mem_fun (*this, &DasosPreproc::onSyscall_orig) );*/
   
   //plgState->oTIE_connection = plg->onTranslateInstructionEnd.connect (sigc::mem_fun (*this, &DasosPreproc::onTranslateInstructionEnd_orig) );
   //plgState->oTIE_RJF_connection = new sigc::connection (s2e()->getCorePlugin()->onTranslateInstructionEnd_RJF.connect (sigc::mem_fun (*this, &DasosPreproc::onTranslateInstructionEnd) ) );
   plgState->oTIE_RJF_connection = plg->onTranslateInstructionEnd_RJF.connect (sigc::mem_fun (*this, &DasosPreproc::onTranslateInstructionEnd) );
   //plgState->oTIE_RJF_connection = plg->onTranslateInstructionEnd_RJF.connect (sigc::mem_fun (*this, &DasosPreproc::onTranslateInstructionEnd) );
   plgState->oTIE_connected = true;
   
   plgState->oTBE_connection = plg->onTranslateBlockEnd.connect (sigc::mem_fun(*this, &DasosPreproc::onTranslateBlockEnd) );
   plgState->oTBE_connected = true;

   plgState->oTBS_connection = plg->onTranslateBlockStart.connect (sigc::mem_fun(*this, &DasosPreproc::onTranslateBlockStart) );
   plgState->oTBS_connected = true;
   
   plgState->oPC_connection = plg->onPrivilegeChange.connect (sigc::mem_fun(*this, &DasosPreproc::onPrivilegeChange) );
   plgState->oExc_connection = plg->onException.connect (sigc::mem_fun(*this, &DasosPreproc::onException) );
   plgState->oPF_connection = plg->onPageFault.connect (sigc::mem_fun(*this, &DasosPreproc::onPageFault) );
   plgState->oTJS_connection = plg->onTranslateJumpStart.connect (sigc::mem_fun(*this, &DasosPreproc::onTranslateJumpStart) );
   plgState->debugs_connected = true;
   
   // flush the translation block cache when possible change happens
   plgState->flushTbOnChange = true;
   
   // init data map, make initial copy
   initDataMap (state);

   return;
} // end fn onActivateModule


// This serves merely to force reconnect any signals
void DasosPreproc::onTranslateBlockStart (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc) {
   if (isInShell (state->getPc () ) ) {
      s2e()->getDebugStream() << " >> oTBS pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << "\n";
      DECLARE_PLUGINSTATE (DasosPreprocState, state);
      plgState->tb_seq_num++;
   }
   return;
} // end fn onTranslateBlockStart


void DasosPreproc::printOOBDebug (S2EExecutionState* state) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // print the trans_trace
   printTransTrace (plgState->trans_trace); //, plgState->code_map);
   //mapExecs ();
   //printMemMap (plgState->code_map, cfg.base_addr);
   return;
} // end fn printOOBDebug


/*void DasosPreproc::validateInsn (S2EExecutionState* state, trans_instance insn, uint8_t* raw) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   plgState->trans_trace.insns.push_back (insn);
   plgState->trans_trace.in_range_insns++;
   plgState->trans_trace.valid_insns++;
   plgState->trans_trace.last_valid = plgState->trans_trace.insns.size () - 1;
   
   // write the bytes into the code_map/snapshot
   // update any statistics as needed
   for (unsigned i = 0; i < insn.len; i++) {
      unsigned pc_i = insn.addr /*- cfg.base_addr*//* + i;
      if (timesUsed (plgState->code_map.back (), pc_i) == 0) {
         byteWrite (plgState->code_map.back (), pc_i, raw[i]);
         plgState->code_map.back().num_used_bytes++;
      }
      timesUsedInc (plgState->code_map.back (), pc_i);
      
      //if (!validated (plgState->code_map.back (), pc_i) ) {
      validate (plgState->code_map.back (), pc_i);
      plgState->code_map.back().num_valid_bytes++;
      
      if (pc_i < plgState->code_map.back().min_addr) {
         plgState->code_map.back().min_addr = pc_i;
      }
      if (pc_i > plgState->code_map.back().max_addr) {
         plgState->code_map.back().max_addr = pc_i;
      }
   }
   
   return;
} // end fn validateInsn


void DasosPreproc::invalidateInsn (S2EExecutionState* state, unsigned idx, trans_instance cause) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // in order to be invalidated, it must have been validated, so it must be in_range, do not mod its value
   plgState->trans_trace.insns[idx].valid = false;
   plgState->trans_trace.valid_insns--;
   for (unsigned i = 0; i < plgState->trans_trace.insns[idx].len; i++) {
      invalidate (plgState->code_map.back (), plgState->trans_trace.insns[idx].addr + i);
      plgState->code_map.back().num_valid_bytes--;
   }
   // now handle min/max addr
   if (cause.addr < plgState->trans_trace.insns[idx].addr) {
      plgState->code_map.back().min_addr = cause.addr;
   }
   // NOTE this messes things up if not physically next addr higher than insns[idx]
   if (plgState->code_map.back().min_addr == plgState->trans_trace.insns[idx].addr && plgState->trans_trace.insns[idx].addr < cause.addr) {
      plgState->code_map.back().min_addr = cause.addr;
   }
   // TODO resolve max_Addr settings
   //if max_addr == 
   // NOTE assumes a repeat is logical and physical next insn, so addr min/max is greater than previous 
   return;
} // end fn invalidateInsn*/


void DasosPreproc::onTransKernInsns (S2EExecutionState* state, uint64_t pc) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   //s2e()->getWarningsStream (state) << "ignore this insn as it is the kernel interrupting things, but not changing the cr3 value at addr 0x" << std::hex << pc << "\n";
   plgState->kernel_insns++;
   plgState->tot_killable_insns++;
   // at some point it can go into the kernel, to another proc, and then back to the kernel (CR3 is changed to the value of another proc)
   // thus pid filtering no longer let's us catch OOB insns and our system will not kill a hung observed proc 
   if (plgState->kernel_insns > MAX_KERNEL_INSNS) {
      s2e()->getWarningsStream (state) << "ERROR: we've left our module/shellcode, within kernel now, for far too long, terminateStateEarly\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state that exec'ed out of module bounds, in the kernel, for too long"), false);
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


void DasosPreproc::onTransOOBInsns (S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t len, uint64_t nextpc) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // if last insn was within_range, ie it just went/jumped to OOB
   if (plgState->within_range) {
      // tell the debug about this, plgState->trans_trace.insns.back() should be a jmp/call
      s2e()->getWarningsStream (state) << "@0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << pc << ", left buffer range after " << std::dec << plgState->in_range_insns << " IoB insns; last IoB insn @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << plgState->trans_trace.insns.back().addr + cfg.base_addr << std::dec << ", disasm in debug.\n";
      printTransInstance (plgState->trans_trace.insns.back() ); //, plgState->code_map, /*plgState->trans_trace.insns.back().snapshot_idx,*/ true);
      // just jumped out of bounds (this is the 1st insn out of range)
      plgState->out_range_insns = 0;
      if (!plgState->expecting_jmp_OOB) {
         s2e()->getWarningsStream (state) << "ERROR: we've left our module/shellcode unexpectedly, terminateStateEarly\n";
         //printOOBDebug (state);
         terminateStateEarly_wrap (state, std::string ("eliminated a state that exec'ed out of module bounds unexpectedly"), false);
         return;
      }
      else { /*if expecting_jmp */
         /* maybe test if isInShell (pc) */ 
         // if (plgState->trans_trace.insns.back().next_pc != pc && plgState->trans_trace.insns.back().other_pc != pc) {
         // if it was a jump that we were expecting, then we'd be at a onTBE.
         // onTBE is before onTIE, so nextpc will have been set to plgState->oTBE_nextpc
         // if they don't match, then something else is executing
         // otherwise we'd be at a later insn (eg start of next block) and nextpc wouldn't match
         // or we'd be at a kernel/other proc task switch and its nextpc (even if a TBE) wouldn't match
         // there could be the case where an OOB is jumping back to the last oTBE_nextpc, but then it'd be !within_range, so never here
         if (nextpc != plgState->oTBE_nextpc) {
            s2e()->getWarningsStream (state) << "ERROR: this jump destination doesn't match what we were expecting\n"; //, terminateStateEarly\n";
            //printOOBDebug (state);
            // rem the following two lines to make assert soft.
            terminateStateEarly_wrap (state, std::string ("eliminated a state that is at unexpected location"), false);
            return;
         }
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
      terminateStateEarly_wrap (state, std::string ("eliminated a state that exec'ed out of module bounds for too long"), false);
      return;
   }
   
   // if it reaches here, then we want to record the OOB insn address into the translation trace
   // ie the pc and len are stored, also !in_range insns don't affect statistics
   trans_instance insn;
   insn.snapshot_idx = 0; // this doesn't really matter
   insn.seq_num = 0;
   insn.ti_seq_num = plgState->ti_seq_num++; // still record the sequence number
   insn.tb_seq_num = plgState->tb_seq_num;
   insn.addr = pc - cfg.base_addr; // NOTE that this is relative like with in_range insns, and maybe should be an int instead of uint, or absolute
   insn.len = len; //tb->lenOfLastInstr;
   insn.next_pc = nextpc; //tb->pcOfNextInstr;
   insn.other_pc = 0;
   insn.in_range = false;
   insn.valid = false;
   // TODO store bytes? into insn.bytes
   // do not increment plgState->trans_trace.in_range_insns
   plgState->trans_trace.insns.push_back (insn);
   
   printOOBInsn (state, insn, plgState->out_range_insns);
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


void DasosPreproc::onTransIOBInsns (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t len, uint64_t nextpc) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   if (!plgState->within_range) {
      // if it just entered our module, and it's entered at least once before, then note the re-entry
      if (plgState->has_entered_range) {
         s2e()->getWarningsStream (state) << "@0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << pc << ", re-entered buffer range after " << std::dec << plgState->out_range_insns << " OoB insns; last OoB insn @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << plgState->trans_trace.insns.back().addr + cfg.base_addr << std::dec << ", disasm in debug.\n";
         printOOBInsn (state, plgState->trans_trace.insns.back(), plgState->out_range_insns);
      }
      // back from being out of bounds
      plgState->in_range_insns = 0;
   }
   
   //s2e()->getDebugStream() << " >> oTIE oTOOBI: 0\n";
   // if we've never been in the range, and we are here now, then note that this is the first time
   bool isFirstInsn = false;
   if (!plgState->has_entered_range) {
      plgState->has_entered_range = true;
      isFirstInsn = true;
      plgState->offset = pc - cfg.base_addr;
   }
   plgState->within_range = true;

   // infinite loop check
   // in an earlier version this merely checked if this PC's time_used > 3; but that would fail on a forloop
   // this sees if we've tried to execute more than MAX_IN_RANGE insns for this instance of being within the buffer
   // see the earlier code where when the buffer is left and then returned to the cnt is reset to 0
   plgState->in_range_insns++;
   if (plgState->in_range_insns > MAX_IN_RANGE_INSNS) {
      s2e()->getWarningsStream (state) << "!! Potential inifinite loop or wandering execution exceeding MAX_IN_RANGE, caught at 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << pc << std::endl;
      terminateStateEarly_wrap (state, std::string ("eliminated this branch which exceeded MAX_IN_RANGE"), false);
      return;
   }
   
   // store translation into trans_trace.

   // get the raw insn bytes from the guest memory
   uint8_t insn_raw[len];
   if (!state->readMemoryConcrete (pc, insn_raw, len) ) {
      s2e()->getWarningsStream (state) << "ERROR: could not read guest memory @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << pc << " to gather ASM insns\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read"), false);
      return;
   }
   // this is the first insn, so see if it is an impossible first
   if (isFirstInsn && isInsnImpossibleFirst (insn_raw, len) ) {
      s2e()->getWarningsStream (state) << "ERROR: this is an impossible first instruction, disasm in debug\n";
      s2e()->getDebugStream() << std::setfill(' ') << std::dec << std::setw (3) << 0 << " " << std::setw(2) << len << "B @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << pc << ":";
      printInsn_raw (insn_raw, len, true);
      s2e()->getDebugStream() << std::endl;
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an impossible first instruction"), false);
      return;
   }
   
   // TODO move this elsewhere, check for previous values by searching the trans_trace, leave mem_map for end
   // move trans_trace storage into onExecuteInsn
   // move memmap manip into onSyscall
   
   // at this point code_map.back() is the proper snapshot and we have read the bytes from memory
   // do two things: 
   //   1) store the instance into the trans_trace; and 
   //   2) store the bytes into the code_map/snapshot
   
   trans_instance insn;
   insn.snapshot_idx = 0; //plgState->code_map.size () - 1;
   insn.seq_num = 0;
   insn.ti_seq_num = plgState->ti_seq_num++;
   insn.tb_seq_num = plgState->tb_seq_num;
   insn.addr = pc - cfg.base_addr;
   insn.len = len;
   insn.next_pc = nextpc;
   insn.other_pc = 0;
   insn.in_range = true;
   insn.valid = true; // maybe don't validate until executed
   insn.bytes.resize (len);
   for (unsigned i = 0; i < len; i++) {
      insn.bytes[i].byte = insn_raw[i];
      //insns.bytes[i].times_used;
      //insns.bytes[i].validated;
   }
   insn.disasm = getDisasmSingle (insn.bytes); // maybe only do if it gets executed
   // do not increment plgState->trans_trace.in_range_insns, do that upon execution
   
   //s2e()->getDebugStream() << " >> oTIE oTOOBI: 3\n";
   // I extended qemu to record the next PC, so ideally this PC should equal the last insn's next_PC
   // TODO at the end of loops it thinks that the next insn is the loop back addr instead of loop.addr + loop.len (the next sequential addr)
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
   
   //s2e()->getDebugStream() << " >> oTIE oTOOBI: 5\n";
   //s2e()->getDebugStream() << ">> Printing Trans_Trace Instance ";
   plgState->trans_trace.insns.push_back (insn);
   printTransInstance (insn); //, plgState->code_map, /*insn.seq_num /plgState->trans_trace.insns.size () - 1,*/ true);
   
   signal->connect (sigc::mem_fun (*this, &DasosPreproc::onExecuteInsn) );
   return;
} // end fn onTransIoBInsns


/*void DasosPreproc::onTranslateInstructionEnd_orig (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc) {
   onTranslateInstructionEnd (signal, state, tb, pc, 0);
   return;
} // end fn onTranslateInstructionEnd_orig*/


void DasosPreproc::onTranslateInstructionEnd (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t nextpc) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   uint64_t len = 0; // TODO insert asserts to make sure that len is set
   if (isInShell (pc) ) {
      len = nextpc - pc;
      // if this is a ctrl flow redirection (end of block where oTBE is_target_valid was true), then nextpc isn't set here, but it is within the tb (not sure why S2E doesn't fetch it)
      if (nextpc == 0xffffffffffffffff || nextpc == 0xffffffff || len > 32) { //((uint64_t) - 1) ) {
      /*if (nextpc == 0xffffffffffffffff) { 
       *if (nextpc == 0xffffffff) { */
         nextpc = plgState->oTBE_nextpc;
         len    = tb->lenOfLastInstr; // TODO make this independent of lenOfLastInstr (use unmodified S2E) //plgState->oTBE_len;
         //nextpc = pc + tb->lenOfLastInstr;
         //len = nextpc - pc;
      }
      // bc TIE is called after TBE, the tb block type is set
      else if (tb->s2e_tb_type == TB_JMP_IND || tb->s2e_tb_type == TB_JMP || tb->s2e_tb_type == TB_COND_JMP) {
         // TB_JMP_IND jmp/ljmp Ev, next_pc works, so no need
         // TB_JMP/TB_COND_JMP jmp/ljmp im/Jb, loopnz, loopz, loop, jecxz, next_pc is next sequential
         s2e()->getDebugStream() << " >> DEBUG jump tb that had nextpc and len set correctly\n";
      }
      s2e()->getDebugStream() << " >> oTIE pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << ":0x" << std::noshowbase << std::setw(2) << std::setfill('0') << pc - cfg.base_addr << " nextpc: " << nextpc << " len: " << std::dec << len << "\n";
   }
   
   /*// DONE Resolved, this no longer happens, but there used to be multiple calls to this fn per PC. 
   if (plgState->trans_trace.insns.size () != 0 && pc == plgState->trans_trace.insns.back().addr ) {
      s2e()->getDebugStream() << "!!* pc == plgState->pcs.back @ 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << std::dec << " of len " << tb->size << "B, the 1st is 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << ((unsigned) (tb->tc_ptr)[0] & 0x000000ff) << std::endl;
      return;
   }*/
   
   // put a test on total non-buffer insns and exit if exceeds a certain level
   if (plgState->tot_killable_insns > MAX_KILLABLE_INSNS) {
      s2e()->getWarningsStream (state) << "ERROR: too many killable insns (tot:" << plgState->tot_killable_insns << ";oob:" << plgState->out_range_insns << ";kern:" << plgState->kernel_insns << ";other:" << plgState->other_procs_insns << "), terminateStateEarly\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state that exec'ed too many killable insns, possible hang or other unexpected error"), false);
      return;
   }
   //if (plgState->tot_killable_insns > (MAX_KILLABLE_INSNS - 100) ) s2e()->getWarningsStream (state) << "killable:!(" << plgState->tot_killable_insns << ")\n";
   
   // handle kernel mode insns with a special case
   if (isInKernMode (pc) ) {
      // plgState->has_entered_range: if the call back is activated and has entered range once
      if (plgState->has_entered_range) {
         //s2e()->getDebugStream() << " >> oTIE oTKI\n";
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
         //s2e()->getDebugStream() << " >> oTIE oTOOBI\n";
         onTransOOBInsns (state, tb, pc, len, nextpc);
      }
      return;
   }
   plgState->out_range_insns = 0;
   
   // this is a legit instruction so reset the killable counter
   plgState->tot_killable_insns = 0;
   
   // at this point is NOT in kern mode, PIDs match, is IoB, regardless of has_entered_range value
   //s2e()->getDebugStream() << " >> oTIE oTIOBI\n";
   onTransIOBInsns (signal, state, tb, pc, len, nextpc);
   
   

   return;
} // end fn onTranslateInstructionEnd



void DasosPreproc::initDataMap (S2EExecutionState* state) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // the initial snapshot is just a dump of the observed memory, so we can compare writes later to original values
   // check if the data memory map has been initialized before we try to access it
   if (plgState->data_map.size () != 0) {
      s2e()->getWarningsStream (state) << "ERROR: data memory map could not be initialized\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state that couldn't init data map"), false);
      return;
   }
   
   //s2e()->getDebugStream() <<  ">> DEBUG " << "initDataMap data_map size pre: " << std::dec << plgState->data_map.size () << "\n";
   
   appendSnapshot (plgState->data_map, cfg.byte_len);
   
   //s2e()->getDebugStream() <<  ">> DEBUG " << "initDataMap data_map size post: " << std::dec << plgState->data_map.size () << "\n";
   
   uint8_t data_tmp[cfg.byte_len];
   if (!state->readMemoryConcrete (cfg.base_addr, data_tmp, cfg.byte_len) ) {
      s2e()->getWarningsStream (state) << "ERROR: could not read guest memory @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << cfg.base_addr << " to gather data\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read"), false);
      return;
   }
   for (unsigned i = 0; i < cfg.byte_len; i++) {
      byteWrite (plgState->data_map.back(), i, data_tmp[i]);
   }
   
   
   printMem_raw (data_tmp, cfg.byte_len, cfg.base_addr);
   //printMemRange (data_tmp, cfg.byte_len);
   // print initial input in its entirity
   /*s2e()->getDebugStream() << ">> Here is the given buffer in its original form:\n";
   plgState->data_map.back().min_addr = 0;
   plgState->data_map.back().max_addr = cfg.byte_len;
   printSnapshot (plgState->data_map.back(), cfg.base_addr, true);
   plgState->data_map.back().min_addr = cfg.byte_len;
   plgState->data_map.back().max_addr = 0;*/
   
   return;
} // end fn initDataMap



// see if addr .. addr+len has been translated
// we really only care if it is in the current block and not executed yet... so TODO add logic for that
bool DasosPreproc::hasBeenTranslated (S2EExecutionState* state, uint64_t addr, unsigned len) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   uint64_t n_base = addr - cfg.base_addr;
   uint64_t n_end  = n_base + len - 1;
   for (unsigned i = 0; i < plgState->trans_trace.insns.size(); i++) {
      uint64_t h_base = plgState->trans_trace.insns[i].addr;
      uint64_t h_end  = plgState->trans_trace.insns[i].addr + plgState->trans_trace.insns[i].len - 1;
      if (!(n_base > h_end || n_end < h_base) ) {
         return true;
      }
   }
   return false;
} // end fn hasBeenTranslated


void DasosPreproc::onDataMemoryAccess (S2EExecutionState* state, klee::ref<klee::Expr> guestAddress, klee::ref<klee::Expr> hostAddress, klee::ref<klee::Expr> value, bool isWrite, bool isIO) {
   // only look at writers from observed memory range that write to within the same memory range
   if (!isInShell (state->getPc () ) || !isWrite) { // || !isInShell (cast<klee::ConstantExpr>(guestAddress)->getZExtValue(64) ) ) {
      return;
   }
   
   if (state->isRunningExceptionEmulationCode()) {
      //We do not check what memory the CPU accesses.
      //s2e()->getWarningsStream() << "Running emulation code" << std::endl;
      return;
   }
   
   if(!isa<klee::ConstantExpr>(guestAddress) || !isa<klee::ConstantExpr>(value)) {
      //We do not support symbolic values yet...
      s2e()->getWarningsStream(state) << "Symbolic memory accesses are not yet supported by MemoryChecker" << std::endl;
      return;
   }
   // All clear, so store this write
   // data memory map is initialized in module initialization
   // check here if a new snapshot needs to be appended
   
   uint64_t addr = cast<klee::ConstantExpr>(guestAddress)->getZExtValue(64);
   unsigned accessSize = klee::Expr::getMinBytesForWidth(value->getWidth());
   uint64_t val = cast<klee::ConstantExpr>(value)->getZExtValue(64);
   
   bool in_range = true;
   
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // now it may be a write from IOB to OOB (like fnstenv)
   if (!isInShell (cast<klee::ConstantExpr>(guestAddress)->getZExtValue(64) ) ) {
      in_range = false;/*
      s2e()->getDebugStream() <<
      " >> oDMA OOB Write by seq_num: " << std::dec << plgState->seq_num <<
      " pc: 0x" << std::hex << state->getPc () <<
      ":0x" << std::hex << (state->getPc () - cfg.base_addr) << 
      " to addr: 0x" << std::hex << addr <<
      " len: " << std::dec << accessSize << "B" <<
      " value: ";
      return;*/
      //plgState->last_OOB_write = cast<klee::ConstantExpr>(guestAddress)->getZExtValue(64);
   }
   
   // TODO detect if there had been a oDMA write within buffer to an already translated insn. If so flush tb buffers or force retranslation
   // there has been change to observed/monitored memory/within buffer, this could be code or potential code
   // if it is within the current basic block we need to retranslate all instructions
   if (in_range && plgState->flushTbOnChange) {
      /*// if within current TB and end of TB
      // look at the last byte of the current TB's last insn (which should be the most recent translated insn)
      if (addr < (plgState->trans_trace.insns.back ().addr + cfg.base_addr) ) {
         s2e()->getDebugStream() << " >> Write within same TB!\n";*/
      // TODO this detects if the byte has been translated EVER, which may cause false positives (extra overhead) you may want to be more selective and ony catch those that have been translated but not yet executed (or translated and within the same TB as current insn)
      if (hasBeenTranslated (state, addr, accessSize) ) {
         s2e()->getDebugStream() << " >> Write to previously translated insn! at pc 0x" << std::hex << addr << "\n";
         // clear the cache, it's invalid now anyways
         //tb_flush(env);
         // I may want to take stronger action if the insn is within the same TB, somehow stop the current TB execution? According to Vitaly you can do this by throwing a CpuExitException
         // It will abort the execution of the current TB. QEMU will retranslate starting from the current instruction pointer on the next fetch/decode iteration.
         plgState->oEI_retranslate = state->getPc ();
      }
      else {
         s2e()->getDebugStream() << " >> Benign write to unused address\n";
      }
   }
   

   data_instance data;
   data.snapshot_idx = plgState->data_map.size () - 1; // I don't think that this matters since the mapping is done after tracing
   data.addr = addr - cfg.base_addr;
   data.len = accessSize;
   data.bytes.resize (data.len);
   data.other_pc = state->getPc (); // to keep things uniform, other_pc and next_pc are absolute
   // TODO should data.seq_num be current seq_num + 1, which is seq_num bc it is already set for next insn (bc oDMA happens before oEI, but this must be IOB/valid/etc)
   data.seq_num = plgState->seq_num; // + 1; //getSeqNum (state, data.other_pc); //plgState->seq_num;
   data.in_range = in_range;
   data.valid = true; 
   
   uint8_t buf[sizeof (uint64_t)];
   // the s2e/qemu system just memcpy a uint8_t* of size X into val from ((uint8_t*)&(val))[0], so to pull it out do the same
   memcpy ((void* ) buf, (void* ) &val, sizeof (uint64_t) );
   for (unsigned i = 0; i < data.len /*sizeof (uint64_t)*/; i++) {      
      //s2e()->getDebugStream() << " >> byte[" << std::dec << i << "]: " << std::setw (2) << std::hex << ((unsigned) buf[i] & 0x000000ff) << " ";
      struct mem_byte byte;
      byte.times_used = 1;
      byte.validated = 0;
      byte.byte = buf[i];
      data.bytes[i] = byte;
   }

   //s2e()->getDebugStream() << "\n";
   if (data.in_range) {
      plgState->write_trace.in_range_bytes += data.len; // TODO not unique bytes!
   }
   plgState->write_trace.writes.push_back (data);
   //delete [] bytes;
   
   s2e()->getDebugStream() << " >> oDMA";
   if (!data.in_range) { s2e()->getDebugStream() << " OOB"; }
   s2e()->getDebugStream() << 
   " Write by seq_num: " << std::dec << data.seq_num <<
   " pc: 0x" << std::hex << data.other_pc <<
   ":0x" << std::hex << (data.other_pc - cfg.base_addr) << 
   " to addr: 0x" << std::hex << (data.addr + cfg.base_addr) <<
   " len: " << std::dec << data.len << "B" <<
   " value: ";
   for (unsigned i = 0; i < data.len; i++) {
      s2e()->getDebugStream() << " 0x" << std::setw (2) << std::hex << ((unsigned) data.bytes[i].byte & 0x000000ff) << " ";
   }
   s2e()->getDebugStream() << "\n";
   
   s2e()->getDebugStream() << " >> >> oDMA value in memory at that address: ";
   uint8_t bytes[8];
   if (!state->readMemoryConcrete (addr, bytes, accessSize) ) {
      s2e()->getWarningsStream (state) << "ERROR: could not read guest memory @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << addr << " to gather data\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read"), false);
      return;
   }
   for (unsigned i = 0; i < data.len; i++) {
      s2e()->getDebugStream() << " 0x" << std::setw (2) << std::hex << ((unsigned) bytes[i] & 0x000000ff) << " ";
   }
   s2e()->getDebugStream() << "\n";
   
   //  NOTE we construct the data_map (see if data_map needs a new snapshot upon each write) at the end.
   
   return;
} // end fn onDataMemoryAccess


// given an address of a writer, find the most recent entry in the insn trans_trace and return that seqnum
// oDMA happens before oEI, so if you search exec_trace, you will not find the PC
/*uint64_t DasosPreproc::getSeqNum (S2EExecutionState* state, uint64_t writer_pc) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   //s2e()->getDebugStream() << " >> Looking for last execution of 0x" << std::hex << writer_pc << "\n";
   for (int i = plgState->trans_trace.insns.size () - 1; i >= 0; i--) {
      //s2e()->getDebugStream() << " >> >> is it: 0x" << std::hex << plgState->trans_trace.insns[i].addr << "\n";
      if (plgState->trans_trace.insns[i].addr == (writer_pc - cfg.base_addr) ) {
         return plgState->trans_trace.insns[i].seq_num;
      }
   }
   return 0;
} // end fn getSeqNum*/


void DasosPreproc::terminateStateEarly_wrap (S2EExecutionState* state, std::string msg, bool success) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   
   // disconnect all the hooks, activateModule might have been called
   if (plgState->oTIE_connected) {
      plgState->oTIE_connection.disconnect ();
      plgState->oTIE_RJF_connection.disconnect ();
      plgState->oTIE_connected = false;
   }
   if (plgState->oTBE_connected) {
      plgState->oTBE_connection.disconnect ();
      plgState->oTBE_connected = false;
   }
   if (plgState->oTBS_connected) {
      plgState->oTBS_connection.disconnect ();
      plgState->oTBS_connected = false;
   }
   if (plgState->oDMA_connected) {
      plgState->oDMA_connection.disconnect ();
      plgState->oDMA_connected = false;
   }
   
   if (plgState->debugs_connected) {
      plgState->oPC_connection.disconnect ();
      plgState->oExc_connection.disconnect ();
      plgState->oPF_connection.disconnect ();
      plgState->oTJS_connection.disconnect ();
      plgState->debugs_connected = false;
   }
   
   // to help with debug, we may be interested in seeing what bytes were written to by this state
   if (!success && plgState->write_trace.writes.size () /*in_range_bytes*/ > 0) {
      s2e()->getDebugStream() << ">> Terminating non-successful state that had " << std::dec << plgState->write_trace.writes.size () << " legitimate writes, outputting its trace and mem_map\n";
      printDataTrace (plgState->write_trace);
      mapWrites (plgState->data_map, plgState->write_trace);
      printMemMap (plgState->data_map, cfg.base_addr);
   }
   // terminate the state
   s2e()->getExecutor()->terminateStateEarly (*state, msg.c_str () );
   return;
} // end fn terminateStateEarly_wrap


/*void DasosPreproc::onSyscall_orig (S2EExecutionState* state, uint64_t pc, LinuxSyscallMonitor::SyscallType sysc_type, uint32_t sysc_number, LinuxSyscallMonitor::SyscallReturnSignal& returnsignal) {
   onSyscall (state, pc, sysc_number);
   return;
} // end fn onSyscall_orig*/


// assumes that any system call is at the end of a block
// TBEs are signalled before TIEs, so this catches the syscall at the end of the last block before any changes happen by the next oTIE
// some reg info and such (dumpX86State) isn't updated until the end of the block is reached
void DasosPreproc::onTranslateBlockEnd (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, bool is_target_valid, uint64_t target_pc) {
   if (!isInShell (pc) ) {
      return;
   }
   
   if (is_target_valid) {
      s2e()->getDebugStream() << " >> oTBE Target by pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " to pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << target_pc << "\n";
      
      DECLARE_PLUGINSTATE (DasosPreprocState, state);
      plgState->oTBE_nextpc = target_pc;
      //plgState->oTBE_len = tb->lenOfLastInstr;
   }
   
   if (tb->s2e_tb_type == TB_INTERRUPT) {
      char insnByte;
      int intNum = -1;
      if (!state->readMemoryConcrete (pc, &insnByte, 1) ) {
         s2e()->getDebugStream() << "Could not read interrupt instruction at 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << "\n";
         terminateStateEarly_wrap (state, "ERROR: could not read int insn type.\n", false);
         return;
      }
      
      // interpret the interrupt insn type (opcode)
      if ((insnByte & 0xFF) == 0xCC) {
         intNum = 3;
      }
      else if ((insnByte & 0xFF) == 0xCD) {
         unsigned char intNumByte;
         if (!state->readMemoryConcrete(pc + 1, &intNumByte, 1)) {
            s2e()->getDebugStream() << "Could not read interrupt index at 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << "\n";
            terminateStateEarly_wrap (state, "ERROR: could not read int number.\n", false);
            return;
         }
         intNum = (int) intNumByte;
      }
      // else invalid opcode
      else {
         s2e()->getDebugStream() << "Unexpected opcode (not cc or cd) at 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << ", value: " << std::hex << std::noshowbase << std::setw(2) << std::setfill('0') << (unsigned int) insnByte << "\n";
         terminateStateEarly_wrap (state, "ERROR: int number invalid range.\n", false);
         return;
      }
      
      // verify that interrupt index (number) is valid
      if (intNum == -1) {
         s2e()->getDebugStream() << "Invalid int number (-1) at 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << "\n";
         terminateStateEarly_wrap (state, "ERROR: int number invalid range.\n", false);
         return;
      }
      
      s2e()->getDebugStream() << " >> oTBE INTERRUPT by pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " int: 0x" << std::hex << std::noshowbase << std::setw(2) << std::setfill('0') << intNum << "\n";
      
      // hook this instuction's pc into a variation of onExecuteInsn, onExecuteSyscall
   }
   
   signal->connect (sigc::mem_fun (*this, &DasosPreproc::onExecuteBlock) );

   
   /*if (plgState->found_syscall) { // only set within transIOB, so this should be in range, our plugin is loaded, etc, but it's all double checked later anyways
      s2e()->getDebugStream() << " >> oTBE with Syscall by pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " to pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << target_pc << "\n";
   // the pc is going to be for the kernel... so use the last known pc
   // assumes that there is no gap in insns that could have changed eax between the insn end and the block end
   //if (cfg.is_loaded && cfg.proc_id == state->getPid () && isInShell (pc) ) {
      uint32_t eax = 0xffffffff;
      if (!(state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(eax), 4 ) ) ) {
         s2e()->getWarningsStream() << "Error: Syscall with symbolic syscall number (EAX)!" << "\n";
         terminateStateEarly_wrap (state, std::string ("Syscall with symbolic syscall number (EAX)!"), false);
         return;
      }
      eax = eax & 0xffffffff; // probably not needed
      //s2e()->getDebugStream() << " this is a syscall insn, with eax of " << std::dec << eax << ", or 0x" << std::hex << std::noshowbase << std::setw(3) << std::setfill('0') << eax << ", @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << pc << "\n";
      //plgState->lastTBE_pc = pc;
      //plgState->lastTBE_eax = eax;
      
      state->dumpX86State(s2e()->getDebugStream () );
      if (plgState->found_syscall > 1) {
         s2e()->getDebugStream() << "ERROR: found more than 1 syscall after 1st syscall was found (" << std::dec << plgState->found_syscall << ")\n";
      }
      // the problem here is that upon oTIE the EAX isn't set yet
      // however, if you use the oTBE after the oTIE that catches the int 80, then the PC is for kernel space
      // even if you capture all oTBEs and use the last one at oTIE, the eax isn't set, not sure of the nuances here, but this works
      onSyscall (state, plgState->trans_trace.insns.back().addr + cfg.base_addr, eax);
   }*/
   return;
} // end fn onTranslateBlockEnd


void DasosPreproc::onExecuteInsn (S2EExecutionState* state, uint64_t pc) {
   if (!isInShell (pc) ) {
      s2e()->getDebugStream() << " >> oEI OOB pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << "\n";
      return;
   }
   s2e()->getDebugStream() << " >> oEI pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << "\n";
   
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   exec_instance e;
   e.snapshot_idx = 0;
   e.addr = pc - cfg.base_addr;
   e.seq_num = plgState->seq_num++;
   e.other_pc = 0;
   e.len = 0;
   //fillInExecInsnFromTransInsn (e, plgState->trans_trace);
   for (int i = plgState->trans_trace.insns.size () - 1; i >= 0; i--) {
      trans_instance* t = &(plgState->trans_trace.insns[i]);
      // assumes that this oEI was hooked by the most recent translation of bytes starting at PC
      if (t->addr == e.addr) {
         e.len = t->len;
         //e.bytes (assign and then set flags as needed) (times_used, validated)
         e.bytes = t->bytes;
         e.next_pc = t->next_pc;
         e.in_range = t->in_range; // unneeded? always true?
         e.valid = t->valid; // unneeded? always true?
         e.ti_seq_num = t->ti_seq_num;
         e.tb_seq_num = t->tb_seq_num;
         e.disasm = t->disasm;
         i = 0;
      }
   }
   if (e.len == 0 || e.bytes.size () != e.len) {
      s2e()->getDebugStream() << " >> ERROR: oEI failed to find a translation, pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << "\n";
      terminateStateEarly_wrap (state, std::string ("ERROR: oEB failed to find a translation"), false);
      return;
   }
   
   plgState->exec_trace.in_range_insns++;
   plgState->exec_trace.valid_insns++;
   plgState->exec_trace.last_valid = pc;
   
   // get bytes from memory and compare to trans' bytes
   uint8_t insn_raw[e.len];
   if (!state->readMemoryConcrete (pc, insn_raw, e.len) ) {
      s2e()->getWarningsStream (state) << "ERROR: could not read guest memory @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << pc << " to gather ASM insns\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read"), false);
      return;
   }
   
   for (unsigned i = 0; i < e.len; i++) {
      if (e.bytes[i].byte != insn_raw[i]) {
         s2e()->getDebugStream() << " >> WARNING: oEI bytes in mem (executed) do not bytes when translated, pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " trans: ";
         for (unsigned j = 0; j < e.len; j++) {
            s2e()->getDebugStream() << std::setw (2) << std::hex << ((unsigned) e.bytes[j].byte & 0x000000ff);
         }
         s2e()->getDebugStream() << " (" << e.disasm << ") raw: ";
         for (unsigned j = 0; j < e.len; j++) {
            s2e()->getDebugStream() << std::setw (2) << std::hex << ((unsigned) insn_raw[j] & 0x000000ff);
         }
         s2e()->getDebugStream() << " (" << getDisasmSingle (insn_raw, e.len) << ")\n";
         //terminateStateEarly_wrap (state, std::string ("ERROR: oEI bytes exec'ed or at PC do not match bytes from translation"), false);
         //return;
         //tb_flush(env); // didn't seem to retranslate things!
      }
   }
   
   // impossible first insns are filtered out in oTIE
   
   handleIfFPU (state, e);
      
   plgState->exec_trace.insns.push_back (e);
   printExecInstance (e);
   
   // if the last oDMA was a write that requires a retranslation, then match its pc to this pc and retranslate the block
   if (plgState->oEI_retranslate == pc) {
      s2e()->getDebugStream() << " >> DEBUG: oEI retranslate triggered at pc 0x" << std::hex << pc << "\n";
      plgState->oEI_retranslate = 0;
      // this causes current execution loop to exit (this may be exception 239), and then pick back up at the pc (which happens to be the next insn; perfect!). By pick back up I mean that it retranslates from PC and then executes that retranslation.
      // https://groups.google.com/forum/?fromgroups=#!topic/s2e-dev/1L9ABYSlw0w
      // You can throw CpuExitException() from your plugin code. It will abort the execution of the current TB. QEMU will retranslate starting from the current instruction pointer on the next fetch/decode iteration. -Vitaly
      throw CpuExitException ();
      /* Example of its usage: https://groups.google.com/forum/?fromgroups=#!searchin/s2e-dev/CpuExitException/s2e-dev/gWyuh_bqEZE/F_WCzFDH83IJ
       * - Read and write any data you want in the CPU state (including the 
       p rogram counter)                                                   *
       For example, the following will set the program counter to 0x1234: 
       
       uint32_t var = 0x1234; 
       state->writeCpuState(offsetof(CPUState, eip), &var, 
       sizeof(uint32_t)*8); 
       
       You can off course also use any other function in the 
       S2EExecutionState object. 
       
       - Issue throw CpuExitException(); 
       This will exit the CPU loop (i.e., abort the execution at the current 
       program counter) and restart execution using the latest CPU state. 
       */
   }

   return;
} // end fn onExecuteInsn


void DasosPreproc::handleIfFPU (S2EExecutionState* state, exec_instance e) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // if fnstenv D9 / 6 ; possibly also fstenv 9B D9 / 6 (and fsav fnsav/fxsav)
   // look at i386-translate.c:5692-ish
   // this insn should write a FPU exception struct to the given address, but the struct isn't handled correctly (the last fpu pc not set upon any fpu insn
   if (e.bytes[0].byte == 0xd9) {
      //s2e()->getDebugStream() << " >> oEI handling FPU stenv pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << e.addr + cfg.base_addr << "\n";
      // oEI happens after oDMA, so we don't need to translate the fnstenv's write address
      // instead just find this insn's write addr within the data_trace (should be the most recent write)
      // look into the write trace and find the last write (eg the write.other_pc that matches e.addr)
      uint64_t write_addr = findWriteAddr (e.addr + cfg.base_addr, plgState->write_trace); //findWriteAddr (e.bytes);
      // adjust to write where the last_fpu_pc is expected to be (offset of last fpu pc within the fpu exception struct)
      write_addr += 0xc;
      s2e()->getDebugStream() << " >> oEI handling FPU stenv pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << e.addr + cfg.base_addr <<  " writing last_fpu_pc: 0x" << plgState->last_fpu_pc << " to target: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << write_addr << "\n"; // (which prob should equal esp i fyou need to double check)\n";
      //state->dumpX86State (s2e()->getDebugStream () );
      if (!state->writeMemoryConcrete(write_addr, &(plgState->last_fpu_pc), sizeof (plgState->last_fpu_pc) ) ) {
         s2e()->getWarningsStream (state) << "ERROR: could not write guest memory @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << write_addr << " to store last_fpu_pc\n";
         terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid write"), false);
         return;
      }
   }
   /* Note that there may be other FPU store env variations:
    * look into fstenv, fstpt, fnsave, etc. */
   // else if fpu any other insn
   //switch (e.bytes[0].byte) {
   // case 0xd8 ... 0xdf:
   if (e.bytes[0].byte == 0xd8 || (e.bytes[0].byte >= 0xda && e.bytes[0].byte <= 0xdf) ) {
         s2e()->getDebugStream() << " >> oEI handling FPU insn pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << e.addr + cfg.base_addr << "\n";
         // store the pc incase fnstenv is called
         plgState->last_fpu_pc = e.addr + cfg.base_addr;
         //break;
      //default :
         //return;
   }
   return;
} // end fn handleIfFPU


// works bc oDMA happens before oEI. 
// If not the case, then you must either translate the instruction to decipher the write addr or set a flag for the next oDMA, if matches this writer addr, then swap in our last_fpu_pc value.
uint64_t DasosPreproc::findWriteAddr (uint64_t writer, Data_Trace t) {
   //s2e()->getDebugStream() << " >> oEI looking in data_trace for FPU stenv pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << writer << "\n";
   // search write_trace backwards looking for writer_pc, upon match return its addr
   // note that 1 insn instance may write many 32/64b times, so you need to catch the earliest write in the latest set of the writes
   for (int i = (t.writes.size () - 1); i >= 0; i--) {
      //s2e()->getDebugStream() << " >> oEI compare: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << writer << " to 0x" << t.writes[i].other_pc << "\n";
      // find the first write addr of the most recent batch of writes for a particular pc
      if ((i == 0 && writer == t.writes[i].other_pc) || (i > 0 && writer == t.writes[i].other_pc && writer != t.writes[i-1].other_pc) ) {
         //s2e()->getDebugStream() << " >> oEI match target was: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << t.writes[i].addr + cfg.base_addr << "\n";
         return t.writes[i].addr + cfg.base_addr;
      }
   }
   return 0;
} // end fn findWriteAddr


void DasosPreproc::onExecuteBlock (S2EExecutionState* state, uint64_t pc) {
   s2e()->getDebugStream() << " >> oEB pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << "\n";
   return;
} // end fn onExecuteBlock


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
      terminateStateEarly_wrap (state, std::string ("wrong syscall found in memory range"), false);
      return;
   }
   
   // Regardless of EIP see if syscall not within range
   if (sysc_number > MAX_SYSCALL_NUM) {
      stream << "!! Wrong syscall number makes no sense (>" << MAX_SYSCALL_NUM << ") " << sysc_number << ":0x" << std::noshowbase << std::setw(2) << std::setfill('0') << std::hex << sysc_number << std::endl;
      terminateStateEarly_wrap (state, std::string ("eliminated this false positive, out of range syscall number found at eip"), false);
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
         terminateStateEarly_wrap (state, std::string ("eliminated this false positive, incorrect syscall number found at eip"), false);
         return;
      }
   }
   
   // TODO make a semantic analysis given the sysc_number, look at the parameters and see if they match up to prototypes
   
   // you could enforce a minimum instruction count here like:
   // if (plgState->exec_trace.insns.size() < 10) { terminateStateEarly }
   
   // All conditions to ignore are ignored, so if it's here, then it must be a positive match...
   // but is it a false positive?

   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   // we need to see if the trans_trace is a subset of a previous successful pcs
   if (!isInsnTraceUnique (plgState->exec_trace, cfg.successes) ) { //, plgState->code_map) ) {
      stream << "!! Unfortunately this execution path is a suffix/subset of a previously found success. This path has " << plgState->exec_trace.insns.size () << " instructions, PCs: ";
      // print out all the PCs for each insn
      for (unsigned int i = 0; i < plgState->exec_trace.insns.size (); i++) {
         if (!isInShell (plgState->exec_trace.insns[i].addr + cfg.base_addr) ) stream << "[";
         stream << std::hex << (plgState->exec_trace.insns[i].addr + cfg.base_addr);
         if (!isInShell (plgState->exec_trace.insns[i].addr + cfg.base_addr) ) stream << "]";
         stream << " ";
      }
      stream << std::endl;
      terminateStateEarly_wrap (state, std::string ("eliminated this false positive, execution path subset of another success"), false);
      return;
   }
   onSuccess (state, pid, pc, sysc_number, lenOfInsn);
   return;
} // end fn onSyscall


void DasosPreproc::onSuccess (S2EExecutionState* state, uint64_t pid, uint64_t pc, uint32_t sysc_number, unsigned len) { 
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   s2e()->getDebugStream() << ">> onSuccess EIP Found. Syscall number 0x" << std::hex << sysc_number << " at addr 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " offset from base: " << std::dec << (pc - cfg.base_addr) << " (should be EIP-" << std::dec << len << ") within pid: " << pid << " number of exec'ed instructions: " << plgState->exec_trace.insns.size () << ". This is success #" << cfg.successes.size () + 1 << "\n";
   
   state->dumpX86State(s2e()->getDebugStream () );
   
   // store the success
   Success s;
   s.trans_trace = plgState->trans_trace;
   s.exec_trace = plgState->exec_trace;
   s.write_trace = plgState->write_trace;
   mapExecs (plgState->code_map, plgState->exec_trace);
   s.code_map = plgState->code_map;
   mapWrites (plgState->data_map, plgState->write_trace);
   s.data_map = plgState->data_map;
   s.eip_addr = pc + len;
   s.offset = plgState->offset;
   getSuccessStats (s);
   printSuccess (s);
   cfg.successes.push_back (s);
   
   // if this is state[0], then we are in normalize/preprocessor mode, so call fini/output a dump
   if (isInNormalizeMode (state) ) {
      onFiniPreproc (state);
   }
   // else
   terminateStateEarly_wrap (state, std::string ("EIP reached, success"), true);
   return;
} // end fn onSuccess


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
      s2e()->getDebugStream() <<  "!! ERROR: successes is wrong size (" << cfg.successes.size () << "\n";
      terminateStateEarly_wrap (state, std::string ("onFiniPreproc successes wrong size"), false);
      return;
   }
   s2e()->getDebugStream() <<  ">>    Printing success " << 0 << "\n";
   printSuccess (cfg.successes[0]);
   s2e()->getDebugStream() <<  ">>    Done printing success " << 0 << "\n";
   
   dumpPreproc (state);
   
   terminateStateEarly_wrap (state, std::string ("EIP reached, preprocessor success"), true);
   return;
} // end fn onFiniPreproc


// write a mem dump of the shellcode at the point of the first syscall
// use rawshell, but TODO somehow note EIP
void DasosPreproc::dumpPreproc (S2EExecutionState* state) {
   uint8_t rawshell[cfg.byte_len];
   // read memory into rawshell
   if (!state->readMemoryConcrete (cfg.base_addr, rawshell, cfg.byte_len) ) {
      s2e()->getWarningsStream (state) << "ERROR: could not read guest memory @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << cfg.base_addr << " to gather rawshell\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read"), false);
      return;
   }
   // write rawshell to file
   std::ofstream raw_out;
   raw_out.open ("preprocessed.rawshell", std::ios::out | std::ios::binary);
   if (!raw_out.is_open () ) {
      s2e()->getWarningsStream (state) << "ERROR: could not open shell file\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid file open"), false);
      return;
   }
   s2e()->getWarningsStream (state) << "Writing preprocessed shellcode to file: preprocessed.rawshell\n";
   
   // write to file
   //fwrite (rawshell, sizeof (uint8_t), cfg.byte_len, shell_file);
   raw_out.write ((const char*) rawshell, sizeof (uint8_t) * cfg.byte_len);
   raw_out.close();
   
   return;
} // end fn dumpPreproc


void DasosPreproc::onFini (S2EExecutionState* state) {
   s2e()->getWarningsStream (state) << ">> Recv'ed onFini custom insn\n";
   s2e()->getDebugStream() <<  ">> Recv'ed onFini custom insn\n"
                               ">> There were " << std::dec << cfg.successes.size () << " successes\n";
   // print the successes and determine which is the best choice (most effective, closest to the true, positive)
   if (cfg.successes.size () > 0) {
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
   } // end if successes
   
   // is there any other data to print out? like stored data traces or something?
   
   //terminateStateEarly_wrap (*state, "onFini called, success", true);
   return;
} // end fn onFini




void DasosPreproc::onPrivilegeChange (S2EExecutionState* state, unsigned prev_level, unsigned curr_level) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   if (plgState->has_entered_range) { // && within_range;  
      s2e()->getDebugStream() << " >> oPC prev: " << std::dec << prev_level << " curr: " << curr_level << "\n";
   }
   return;
} // end fn onPrivilegeChange


/********************
 * Exception_idx   Short Description
 * 0x00  Division by zero
 * 0x01  Debugger
 * 0x02  NMI
 * 0x03  Breakpoint
 * 0x04  Overflow
 * 0x05  Bounds
 * 0x06  Invalid Opcode
 * 0x07  Coprocessor not available
 * 0x08  Double fault
 * 0x09  Coprocessor Segment Overrun (386 or earlier only)
 * 0x0A  Invalid Task State Segment
 * 0x0B  Segment not present
 * 0x0C  Stack Fault
 * 0x0D  General protection fault
 * 0x0E  Page fault
 * 0x0F  reserved
 * 0x10  Math Fault
 * 0x11  Alignment Check
 * 0x12  Machine Check
 * 0x13  SIMD Floating-Point Exception
 * */
void DasosPreproc::onException (S2EExecutionState* state, unsigned exception_idx, uint64_t pc) {
   if (isInShell (pc) ) {
      s2e()->getDebugStream() << " >> oExc pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " exception_idx: " << std::dec << exception_idx << "(0x" << std::hex << std::noshowbase << std::setw(2) << std::setfill('0') << exception_idx << ")\n";
      //state->dumpX86State(s2e()->getDebugStream () );
      // 0x80 128d is softawre interrupt
      if (exception_idx == 0x80) {
         // get eax register
         uint64_t int_num = 0;
         bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &(int_num), 4);
         int_num = int_num & 0xffffffff;
         if (!ok) {
            s2e()->getWarningsStream (state) << "ERROR: symbolic argument was passed to s2e_op in DasosPreproc onException\n";
            return;
         }
         s2e()->getDebugStream() << " >> oExc INT 0x80 pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " syscall_num: " << std::dec << int_num << "(0x" << std::hex << std::noshowbase << std::setw(2) << std::setfill('0') << int_num << ")\n";
         //state->dumpX86State(s2e()->getDebugStream () );
         // onExc happens before oEI, and if we are here, this state will end before any oEI can be called (fail or success)
         // so the syscall's trans isn't added to the exec_trace, call onExecuteInsn as well!
         onExecuteInsn (state, pc);
         onSyscall (state, pc, int_num);
      }
   }
   return;
} // end fn onException


void DasosPreproc::onPageFault (S2EExecutionState* state, uint64_t addr, bool iswrite) {
   //if (isInShell (addr) ) {
   DECLARE_PLUGINSTATE (DasosPreprocState, state);
   if (plgState->has_entered_range) { // && within_range;  
      s2e()->getDebugStream() << " >> oPF addr: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << addr << " iswrite: " << std::dec << iswrite << "\n";
      state->dumpX86State(s2e()->getDebugStream () );
   }
   return;
} // end fn onPageFault


void DasosPreproc::onTranslateJumpStart (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, int jump_type) {
   if (!isInShell (pc) ) {
      return;
   }
   s2e()->getDebugStream() << " >> oTJS pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " jump_type: " << std::dec << jump_type << "\n";
   return;
} // end fn onTranslateJumpStart




void DasosPreproc::printSuccess (Success s) {
   s2e()->getDebugStream() << ">> Success from offset " << s.offset << "\n";
   s2e()->getDebugStream() << ">> Success densities, overlay: " << s.overlay_density << "; avg: " << s.avg_density << "\n";
   s2e()->getDebugStream() << ">> Success eip: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << s.eip_addr << " offset from base: " << std::dec << (s.eip_addr - cfg.base_addr) <<"\n";
   printTransTrace (s.trans_trace);//, s.code_map);
   s2e()->getDebugStream() << "\n";
   printExecTrace (s.exec_trace);
   printMemMap (s.code_map, cfg.base_addr);
   printDataTrace (s.write_trace);
   printMemMap (s.data_map, cfg.base_addr);
   return;
} // end fn printSuccess


/*
// see if byte, has changed between, iteratively, m.back() .. m[0]
bool DasosPreproc::hasByteChanged (uint8_t val, Mem_map m, uint64_t addr) {
   //byte (s, addr) != d.writes[i].bytes[j].byte) { recursively for all snapshots until last used one found
   s2e()->getDebugStream() <<  "!! size: " << std::dec << m.size () << " addr: " << std::hex << addr << " val: " << std::hex << val << "\n";
   for (int i = (m.size () - 1); i >= 0; i--) {
      s2e()->getDebugStream() <<  "!! i: " << std::dec << i << "\n";
      s2e()->getDebugStream() <<  "!! times: " << std::dec << timesUsed (m[i], addr) << std::hex << " byte: " << std::hex << byte (m[i], addr) << "\n";
      // if m[0] (initial snapsot is a special case, not marked as used until a copy on write happens)
      // OR if this current or earlier snapshot used this byte and the value is different
      if ((i == 0 || timesUsed (m[i], addr) > 0) && byte (m[i], addr) != val) {
         s2e()->getDebugStream() <<  "!! CHANGED \n";
         return true;
      }
   }
   s2e()->getDebugStream() <<  "!! NOT CHANGED \n";
   return false;
} // end fn hasByteChanged*/


// TODO mapExecs (plgState->code_map, plgState->exec_trace);
void DasosPreproc::mapExecs (Mem_map& m, Exec_Trace e) {
   // there should be at least no existing snapshots
   if (m.size () != 0) {
      s2e()->getDebugStream() <<  "!! ERROR: code_map is wrong size (" << m.size () << ")\n";
      return;
      //terminateStateEarly_wrap (state, std::string ("mapExecs, code_map wrong size"), false);
   }
   appendSnapshot (m, cfg.byte_len);
   
   // foreach IOB execution
   for (unsigned i = 0; i < e.insns.size (); i++) {
      exec_instance* ei = &(e.insns[i]);
      bool valid = true;
      if (!ei->in_range) { // alt: if (isInShell (ei->addr) ) {
         valid = false;
      }
      //if (isInsnRepeat (e.insns[i], plgState->trans_trace.insns[plgState->trans_trace.last_valid]) { valid = false; }
      //if (ignorable preface/first instructions, such as '90 90') { valid = false; }
      
      // if we want to use this insn
      if (valid) {
         // see if this will need a new snapshot
         // eg check to make sure that this insn isn't diff at any bytes prev called
         // saves peddling back on execution path
         // ie redoing beginning bytes (decrementing times_used and then putting into new snapshot) if changed byte is in middle of insn
         // while doing the loop check for infinite loops
         bool changed = false;
         for (unsigned j = 0; !changed && j < ei->bytes.size (); j++) {
            // if byte at pc + i is in code_map (has been used at least once), then see if it matches the raw byte in guest memory at pc + i
            uint32_t t = timesUsed (m.back (), ei->addr + j);
            if (t == 0) {
               //if (isInNormalizeMode (state) ) s2e()->getDebugStream() << ">> -\n"; // show a marker per new byte execution
            }
            else { // t > 0) {
               //if (isInNormalizeMode (state) ) s2e()->getDebugStream() << ">> ^\n"; // show a marker per prev exec'ed byte execution
               uint8_t b = byte (m.back (), ei->addr + j);
               if (b != ei->bytes[j].byte) {
                  s2e()->getDebugStream() << ">> A byte at offset " << std::dec << i << " has been changed, times_exec'ed before now: " << t << ", orig val: " << std::hex << b << ", new val: " << ei->bytes[j].byte << "\n";
                  // TODO get current snapshot final stats
                  // do assert on num_used_bytes > 0 && max > min
                  m.back().density = m.back().num_used_bytes / (m.back().max_addr - m.back().min_addr + 1);
                  appendSnapshot (m, cfg.byte_len);
                  changed = true; // end forloop
               }
            }
         } // end see if any bytes have been changed
         
         // so now we are either (if changed or never yet written) writing bytes to a new snapshot or (if not changed) just timesUsedInc
         // store bytes into map
         for (unsigned j = 0; j < ei->bytes.size (); j++) {
            if (changed || timesUsed (m.back (), ei->addr + j) == 0) {
               byteWrite (m.back (), ei->addr + j, ei->bytes[j].byte);
               m.back ().num_used_bytes++;
               validate (m.back (), ei->addr + j);
               m.back().num_valid_bytes++;
            }
            timesUsedInc (m.back (), ei->addr + j);
         }
         
         // update the min and max addr
         if (ei->addr < m.back().min_addr) {
            m.back().min_addr = ei->addr;
         }
         if (ei->addr + ei->len > m.back().max_addr) {
            m.back().max_addr = ei->addr + ei->len;
         }
      } // end if we want to look at this insn
   } // end foreach exec'ed insn
   
   return;
} // end fn mapExecs
   

void DasosPreproc::mapWrites (Mem_map& m, Data_Trace d) {
   // there should be at least 1 map of the initial memory
   if (m.size () != 1) {
      s2e()->getDebugStream() <<  "!! ERROR: data_map is wrong size (" << m.size () << ")\n";
      return;
      //terminateStateEarly_wrap (state, std::string ("mapWrites, data_map wrong size"), false);
   }
   // assumes that m[0] is the init'ed snapshot of entire memory space/dump
   appendSnapshot (m, cfg.byte_len);
   
   uint64_t last_write_seq_num = 0;
   // for each write
   for (unsigned i = 0; i < d.writes.size (); i++) {
      if (i == 0) {
         last_write_seq_num = d.writes[i].seq_num;
      }
      if (d.writes[i].in_range) {
         // for each byte within write, store into snapshot if equal or empty, otherwise make new snapshot and store there
         for (unsigned j = 0; j < d.writes[i].bytes.size (); j++) {
            bool byte_changed = false;
            bool same_cluster = false;
            uint64_t addr = d.writes[i].addr + j;
            
            //s2e()->getDebugStream() << " >> DEBUG mapWrites d.writes[" << std::dec << i << "].addr + " << j << ": " << std::hex << addr << "\n"; 
            
            //byte_changed = hasByteChanged (d.writes[i].bytes[j].byte, m, addr);
            if (timesUsed (m.back (), addr) == 0 || (timesUsed (m.back (), addr) != 0 && byte (m.back (), addr) != d.writes[i].bytes[j].byte) ) {
               byte_changed = true;
            }
            //same_cluster = hasClusterChanged (d.writes[i].seq_num, plgState->last_write_seq_num);
            if ((d.writes[i].seq_num - last_write_seq_num) < 11) {
               same_cluster = true;
            }
            
            
            /* there are 3 actions
            * 1) inc times used (keep existing snapshot but do not write value to it) <- always done
            * 2) make a new snapshot (see below)
            * 3) write value to existing snapshot
            * 
            * there are two reasons to make a new snapshot
            * 1) the byte value has changed and timesUsed != 0
            * 2) the clustering difference is too great
            * 
            * conversely reasons to keep using currently snapshot
            * 1) byte is the same
            * 2) timesUsed == 0
            * 3) clustering difference within range
            * 
            * thre are reasons to write value
            * 1) you made a new snapshot
            * 2) the byte in the snapshot is not used (timesUsed == 0) (detectable once you make a new snapshot)
            */
            //bool inc_times_used = false;
            bool append_snapshot = false;
            //bool write_byte = false;
            
            // assign actions given combination of reasons
            if ((byte_changed && timesUsed (m.back (), addr) != 0) || !same_cluster) { // 
               append_snapshot = true;
            }
            
            //s2e()->getDebugStream() << " >> DEBUG mapWrites byte_changed " << std::dec << byte_changed << " same_cluster " << std::dec << same_cluster << " append_snapshot " << append_snapshot << " timesUsed " << timesUsed (m.back (), addr) << " seq_num " << d.writes[i].seq_num << " last_write_seq_num " << last_write_seq_num << "\n";
            // b && u || !c: if cluster is diff or if used and byte diff; covers b.u.c, b.u.!c, b.!u.!c, !b.u.!c, !b.!u.!c
            // testing for !u regardless of making new snapshot (after you would have made it) covers b.!u.c. (eg currently empty/unused byte)
            // !b.u.c: byte is unchanged and byte is used, just inc times used
            // !b.!u.c: byte is unchanged and byte is not used shouldn't happen

            if (append_snapshot) {
               // make sure that current snapshot has min and max set properly
               // get current snapshot stats, ie density
               if (m.back().num_used_bytes == 0 || m.back().max_addr < m.back().min_addr) {
                  s2e()->getDebugStream() << " >> ERROR: appending snapshot when something wrong with current: num_used_bytes " << std::dec << m.back().num_used_bytes << " max_addr " << m.back().max_addr << " min_addr " << m.back().min_addr << "\n";
                  // terminateStateEarly_wrap (state, std::string ("bad snapshot in data map"), false);
                  return;
               }
               m.back().density = m.back().num_used_bytes / (m.back().max_addr - m.back().min_addr + 1);
               appendSnapshot (m, cfg.byte_len);
            }
            
            if (timesUsed (m.back (), addr) == 0) {
               byteWrite (m.back (), addr, d.writes[i].bytes[j].byte);
               if (timesUsed (m.back (), addr) == 0) { 
                  m.back().num_used_bytes++;
                  validate (m.back (), addr);
                  m.back().num_valid_bytes++;
               }
               // store min and max_addr
               if (addr < m.back().min_addr) {
                  m.back().min_addr = addr;
               }
               if (addr > m.back().max_addr) {
                  m.back().max_addr = addr;
               }
            }
            
            //if (inc_times_used) {
            // consider adding if timesUsed == 0 then write it anyways, it might be weird to have timesUsed > 0 and no value appear, regardless if it is the same as the write to the previous snapshot
            timesUsedInc (m.back (), addr);
            if (timesUsed (m.front (), addr) == 0) {
               m.front().num_used_bytes++;
               validate (m.front (), addr);
               m.front().num_valid_bytes++;
            }
            timesUsedInc (m.front (), addr);
            // store min and max_addr
            if (addr < m.front().min_addr) {
               m.front().min_addr = addr;
            }
            if (addr > m.front().max_addr) {
               m.front().max_addr = addr;
            }
            //}
         } // end for each data write's byte
         last_write_seq_num = d.writes[i].seq_num;
      }
   } // end for each data write
   // do assert on num_used_bytes > 0 && max > min
   m.front().density = m.front().num_used_bytes / (m.front().max_addr - m.front().min_addr + 1);
   
   return;
} // end fn mapWrites


void DasosPreproc::printDataTrace (Data_Trace d) {
   s2e()->getDebugStream() << ">> Printing Data_Trace (bytes written in order of write)\n";
   for (unsigned i = 0; i < d.writes.size (); i++) {
      s2e()->getDebugStream() << ">>    ";
      printWriteInstance (d.writes[i]/*, m, i, true*/);
   }
   return;
} // end fn printDataTrace


void DasosPreproc::printWriteInstance (data_instance w) {
   s2e()->getDebugStream() << std::setfill(' ') << std::dec << std::setw (3) << w.seq_num << " by:0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << w.other_pc << " wrote " << std::setfill(' ') << std::dec << std::setw(2) << w.len << "B @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << (w.addr + cfg.base_addr) << ":";
   
   s2e()->getDebugStream() << " ";
   // if the insn was out of bounds, then we didn't capture the byte values
   if (!w.in_range) {
      s2e()->getDebugStream() << "OOB ";
   }
   
   for (uint8_t i = 0; i < w.bytes.size (); i++) {
      s2e()->getDebugStream() << std::setw (2) << std::hex << ((unsigned) w.bytes[i].byte & 0x000000ff) << " ";
   }
   s2e()->getDebugStream() << "\n";
   return;
} // end fn printWriteInstance 


void DasosPreproc::printExecTrace (Exec_Trace e) { //, Mem_map m) {
   s2e()->getDebugStream() << ">> Printing Exec_Trace (instructions in order of execution)\n";
   for (unsigned i = 0; i < e.insns.size (); i++) {
      s2e()->getDebugStream() << ">>    ";
      printExecInstance (e.insns[i]); //, m, /*i,*/ true);
   }
   return;
} // end fn printExecTrace


void DasosPreproc::printTransTrace (Trans_Trace t) { //, Mem_map m) {
   s2e()->getDebugStream() << ">> Printing Trans_Trace (instructions in order of translation)\n";
   for (unsigned i = 0; i < t.insns.size (); i++) {
      s2e()->getDebugStream() << ">>    ";
      printTransInstance (t.insns[i]); //, m, /*i,*/ true);
   }
   return;
} // end fn printTransTrace


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


void DasosPreproc::printExecInstance (exec_instance insn) {
   printEventInstance ((event_instance_t) insn);
} // end fn printExecInstance


void DasosPreproc::printTransInstance (trans_instance insn) {
   printEventInstance ((event_instance_t) insn);
} // end fn printTransInstance


void DasosPreproc::printEventInstance (event_instance_t insn) {
   s2e()->getDebugStream() << std::setfill(' ') << std::dec << std::setw (3) << insn.seq_num << ":" << std::setw (3) << insn.ti_seq_num << ":" << std::setw (2) << insn.tb_seq_num << " " << std::setw(2) << insn.len << "B @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << (insn.addr + cfg.base_addr) << ":";
   // if the insn was out of bounds, then we didn't capture the byte values
   if (!insn.in_range) {
      s2e()->getDebugStream() << " OOB, bytes not captured\n";
      // TODO use the PC and the symbol table to guess where it came from, for instance another internal fn or a standard library
      return;
   }
   
   //uint8_t raw[insn.len];
   unsigned printed_width = 0;
   for (unsigned i = 0; i < insn.len; i++) {
      uint8_t b = insn.bytes[i].byte; //byte (m[insn.snapshot_idx], insn.addr + i);
      //raw[i] = b;
      if (insn.bytes[i].times_used > 1) { // timesUsed (m[insn.snapshot_idx], insn.addr + i) > 1) {
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
   if (insn.disasm.length () == 0) {
      s2e()->getDebugStream() << " no disasm stored";
   }
   else {
      s2e()->getDebugStream() << insn.disasm;
   }
   if (!insn.valid) {
      s2e()->getDebugStream() << "  *vestigial*";
   }
   s2e()->getDebugStream() << " nextPC: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.next_pc;
   //if (insn.other_pc != 0x00000000 && insn.other_pc != insn.next_pc) s2e()->getDebugStream() << " jmpPc: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.other_pc;
   s2e()->getDebugStream() << std::endl;
   return;
} // end fn printEventInstance


void DasosPreproc::printOOBInsn (S2EExecutionState* state, trans_instance insn, unsigned num_oob) {
   // there is no memory snapshot, this is taken directly from memory
   // get the raw insn bytes from the guest memory
   uint8_t raw[insn.len];
   // NOTE that in order to work, the original pc must have been greater in value than cfg.base_addr
   if (!state->readMemoryConcrete (insn.addr + cfg.base_addr, raw, insn.len) ) {
      s2e()->getWarningsStream (state) << "ERROR: could not read guest memory @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.addr + cfg.base_addr << " to gather ASM insns\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read"), false);
      return;
   }
   s2e()->getDebugStream() << std::setfill(' ') << std::dec << std::setw (3) << insn.ti_seq_num << ":" << std::setw (3) << num_oob << " " << std::setw(2) << insn.len << "B @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << (insn.addr + cfg.base_addr) << ":";
   printInsn_raw (raw, insn.len, true);
   s2e()->getDebugStream() << " nextPC: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.next_pc;
   //if (insn.other_pc != 0x00000000 && insn.other_pc != insn.next_pc) s2e()->getDebugStream() << " jmpPc: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.other_pc;
   s2e()->getDebugStream() << std::endl;
   return;
} // end fn printOOBInsn



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


std::string DasosPreproc::getDisasmSingle (uint8_t* raw, unsigned len) {
   std::string disasm; // = "";
   ud_t ud_obj;
   ud_init (&ud_obj);
   ud_set_mode (&ud_obj, 32);
   ud_set_syntax (&ud_obj, UD_SYN_INTEL);
   
   ud_set_input_buffer(&ud_obj, raw, len);
   
   unsigned insn_len = 0;
   if ((insn_len = ud_disassemble (&ud_obj) ) != len) {
      disasm = "disasm didn't do all insn bytes"; //: " + itoa(insn_len) + "/" + itoa(len);
      return disasm;
   }
   char buf[64];
   snprintf (buf, sizeof (buf), " %-24s", ud_insn_asm (&ud_obj) );
   disasm += buf;
   return disasm;
} // end fn getDisasmSingle


std::string DasosPreproc::getDisasmSingle (std::vector<struct mem_byte> bytes) {
   uint8_t raw[bytes.size ()];
   for (unsigned i = 0; i < bytes.size (); i++) {
      raw[i] = bytes[i].byte;
   }
   return getDisasmSingle (raw, bytes.size () );
} // end fn getDisasmSingle


void DasosPreproc::printMemMap (Mem_map m, uint64_t base) {
   s2e()->getDebugStream() << ">> Printing the memory map (" << m.size () << " snapshots)\n";
   for (unsigned i = 0; i < m.size (); i++) {
      s2e()->getDebugStream() << ">>    Printing snapshot " << i << "\n";
      printSnapshot (m[i], base, false);
   }
   return;
} // end fn printMemMap


void DasosPreproc::printMem_raw (uint8_t* raw, unsigned raw_len, uint64_t base) {
   unsigned curr_addr, end_addr, i, j;
   char buf[1024];
   
   //unsigned min_addr = base;
   //unsigned max_addr = base + raw_len;
   
   // align for print out
   curr_addr = base & 0xfffffff0;
   end_addr = base + raw_len;
   //s2e()->getDebugStream() << ">>    The density (0 to 1) of this state's path is (" << std::dec << s.num_valid_bytes << "/" << (end_addr - min_addr + 1) << ") = " << s.density << std::endl;
   snprintf (buf, sizeof (buf), ">>    Mem_map start_addr: 0x%08x, length: %uB, end_addr: 0x%08x\n", (unsigned) base, raw_len, end_addr);
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
            if (curr_addr < base) {
               snprintf (buf, sizeof (buf), "  ");
               s2e()->getDebugStream() << buf;
            }
            else if (curr_addr <= end_addr) {
               char tmp = raw[curr_addr - base];
               snprintf (buf, sizeof (buf), "%02x", (unsigned int) tmp & 0x000000ff);
               s2e()->getDebugStream() << buf;
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
   s2e()->getDebugStream() << "\n";
   
   return;
} // end fn printMem_raw


void DasosPreproc::printSnapshot (Snapshot s, uint64_t base, bool force_print) {
   // Print dump as already coded using snapshot.mem_bytes[i].byte
   unsigned curr_addr, end_addr, i, j;
   char buf[1024];
   
   unsigned min_addr = s.min_addr + base;
   unsigned max_addr = s.max_addr + base;
    
   // align for print out
   curr_addr = min_addr & 0xfffffff0;
   end_addr = max_addr;
   s2e()->getDebugStream() << ">>    The density (0 to 1) of this state's path is (" << std::dec << s.num_valid_bytes << "/" << (end_addr - min_addr + 1) << ") = " << s.density << std::endl;
   snprintf (buf, sizeof (buf), ">>    Mem_map start_addr: 0x%08x, length: %uB, valid bytes: %u, used bytes: %u, range: %uB, end_addr: 0x%08x\n", min_addr, (unsigned) (s.max_addr - s.min_addr), s.num_valid_bytes, s.num_used_bytes, end_addr - min_addr + 1, end_addr);
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
               if (force_print || ((timesUsed (s, (curr_addr - base) ) != 0) && validated (s, (curr_addr - base) ) ) ) { 
                  char tmp = byte (s, (curr_addr - base) );
                  snprintf (buf, sizeof (buf), "%02x", (unsigned int) tmp & 0x000000ff);
                  s2e()->getDebugStream() << buf;
                  ascii_out[(i * 4) + j] = isprint (tmp) ? tmp : '.';
               }
               else {
                  //if (timesUsed (s, (curr_addr - base) ) == 0 || !validated (s, (curr_addr - base) ) ) {
                  s2e()->getDebugStream() << "--";
                  ascii_out[(i * 4) + j] = '.';
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


void DasosPreproc::appendSnapshot (Mem_map& map, unsigned len) {
   Snapshot s;
   s.mem_bytes.resize (len);
   for (unsigned i = 0; i < len; i++) {
      s.mem_bytes[i].times_used = 0;
      s.mem_bytes[i].validated = false;
   }
   s.density = 0;
   s.num_used_bytes = 0;
   s.num_valid_bytes = 0;
   s.min_addr = len;
   s.max_addr = 0;
   map.push_back (s);
   return;
} // end fn appendSnapshot
 
 
unsigned DasosPreproc::timesUsed (Snapshot s, uint64_t pc) {
   if (s.mem_bytes.size () <= pc) {
      return 0;
   }
   return s.mem_bytes[pc].times_used;
} // end fn timesUsed


uint8_t DasosPreproc::byte (Snapshot s, uint64_t pc) {
   // this also checks if pc is in range
   if (timesUsed (s, pc) <= 0) {
      return 0;
   }
   return s.mem_bytes[pc].byte;
} // end fn byte


bool DasosPreproc::validated (Snapshot s, uint64_t pc) {
   if (s.mem_bytes.size () <= pc) {
      return false;
   }
   return s.mem_bytes[pc].validated;
} // end fn validated


void DasosPreproc::timesUsedInc (Snapshot& s, uint64_t pc) {
   if (s.mem_bytes.size () <= pc) {
      return;
   }
   s.mem_bytes[pc].times_used++;
   return;
} // end fn timesUsedInc


void DasosPreproc::byteWrite (Snapshot& s, uint64_t pc, uint8_t value) {
   if (s.mem_bytes.size () <= pc) {
      return;
   }
   s.mem_bytes[pc].byte = value;
   return;
} // end fn byteWrite 


void DasosPreproc::validate (Snapshot& s, uint64_t pc) {
   if (s.mem_bytes.size () <= pc) {
      return;
   }
   s.mem_bytes[pc].validated = true;
   return;
} // end fn validated


void DasosPreproc::invalidate (Snapshot& s, uint64_t pc) {
   if (s.mem_bytes.size () <= pc) {
      return;
   }
   s.mem_bytes[pc].validated = false;
   return;
} // end fn invalidated
 
 






void DasosPreproc::fuzzFork (S2EExecutionState* state, unsigned int start, unsigned int end) {
   /** Emulate fork via WindowsApi forkRange Code */
   unsigned int i;
   
   //assert(m_functionMonitor);
   klee::ref<klee::Expr> symb = state->createSymbolicValue (klee::Expr::Int32, "fuzz_symb");
   S2EExecutionState* curState = state;
   // by making this 1 shy of iterations you can leverage i value afterwards and the first input state so it doesn't go to waste
   for (i = start; i < end; i++) {
      //s2e()->getDebugStream () << "fuzzClone: 2 " << std::endl;
      klee::ref<klee::Expr> cond = klee::NeExpr::create (symb, klee::ConstantExpr::create (i, klee::Expr::Int32) );
      //s2e()->getDebugStream () << "fuzzClone: 3 " << std::endl;
      klee::Executor::StatePair sp = s2e()->getExecutor()->fork (*curState, cond, false);
      //s2e()->getDebugStream () << "fuzzClone: 4 " << std::endl;
      S2EExecutionState* ts = static_cast<S2EExecutionState* >(sp.first);
      S2EExecutionState* fs = static_cast<S2EExecutionState* >(sp.second);
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
   S2EExecutionState* fs = static_cast<S2EExecutionState* >(sp.second);
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
   oTIE_connected = false;
   oTBE_connected = false;
   oTBS_connected = false;
   oDMA_connected = false;
   debugs_connected = false;
   flushTbOnChange = false;
   oEI_retranslate = 0;
   has_entered_range = false;
   within_range = false;
   seq_num = 0;
   in_range_insns = 0;
   out_range_insns = 0;
   other_procs_insns = 0;
   tot_killable_insns = 0;
   trans_trace.in_range_insns = 0;
   trans_trace.valid_insns = 0;
   write_trace.in_range_bytes = 0;
   kernel_insns = 0;
   pc_of_next_insn_from_last_IoB = 0;
   pc_of_next_insn = 0;
   expecting_jmp_OOB = false;
   //found_syscall = 0;
   ti_seq_num = 0;
   tb_seq_num = 0;
   oTBE_nextpc = 0;
   last_fpu_pc = 0;
} // end fn DasosPreprocState


DasosPreprocState::DasosPreprocState (S2EExecutionState* s, Plugin* p) {
   oTIE_connected = false;
   oTBE_connected = false;
   oTBS_connected = false;
   oDMA_connected = false;
   debugs_connected = false;
   flushTbOnChange = false;
   oEI_retranslate = 0;
   has_entered_range = false;
   within_range = false;
   seq_num = 0;
   in_range_insns = 0;
   out_range_insns = 0;
   other_procs_insns = 0;
   tot_killable_insns = 0;
   trans_trace.in_range_insns = 0;
   trans_trace.valid_insns = 0;
   write_trace.in_range_bytes = 0;
   kernel_insns = 0;
   pc_of_next_insn_from_last_IoB = 0;
   pc_of_next_insn = 0;
   expecting_jmp_OOB = false;
   //found_syscall = 0;
   ti_seq_num = 0;
   tb_seq_num = 0;
   oTBE_nextpc = 0;
   last_fpu_pc = 0;
} // end fn DasosPreprocState


DasosPreprocState::~DasosPreprocState () {
   if (oTIE_connected) {
      oTIE_connection.disconnect ();
      oTIE_RJF_connection.disconnect ();
   }
   oTIE_connected = false;
   if (oTBE_connected) {
      oTBE_connection.disconnect ();
   }
   oTBE_connected = false;
   if (oTBS_connected) {
      oTBS_connection.disconnect ();
   }
   oTBS_connected = false;
   if (oDMA_connected) {
      oDMA_connection.disconnect ();
   }
   oDMA_connected = false;
   if (debugs_connected) {
      oPC_connection.disconnect ();
      oExc_connection.disconnect ();
      oPF_connection.disconnect ();
      oTJS_connection.disconnect ();
   }
   debugs_connected = false;
} // end fn ~DasosPreprocState


PluginState* DasosPreprocState::clone () const {
   return new DasosPreprocState (*this);
} // end fn clone


PluginState* DasosPreprocState::factory (Plugin* p, S2EExecutionState* s) {
   return new DasosPreprocState (s, p);
} // end fn factory





} // namespace plugins
} // namespace s2e


#endif

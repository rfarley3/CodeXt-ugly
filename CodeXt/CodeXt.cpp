#ifndef S2E_PLUGINS_CODEXT_CPP
#define S2E_PLUGINS_CODEXT_CPP

extern "C" {
#include "config.h"
#include "qemu-common.h"
extern struct CPUX86State* env;
}

#include "CodeXt.h"
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Plugins/Opcodes.h>
#include <s2e/ConfigFile.h>

/* code of klee can be found online at: https://www.doc.ic.ac.uk/~dsl11/klee-doxygen/Ref_8h_source.html#l00049 */

extern struct CPUX86State* env;
extern s2e::S2EExecutionState* state;

namespace s2e {
namespace plugins {

//Define a plugin whose class is CodeXt and called "CodeXt".
S2E_DEFINE_PLUGIN(CodeXt, "Finds shellcode within a memory dump. Unpacks obfuscated shellcode.", "CodeXt");


void CodeXt::initialize() {
	setSyscNames ();
		
   cfg.is_loaded   = false;
	cfg.loc_valid   = false;
	cfg.len_valid   = false;
   cfg.eip_valid   = false;
   cfg.sysc_valid  = false;
   cfg.has_printed = false;
	
   //cfg.has_forked  = false;
	cfg.elf_mode = false;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".elfMode") ) {
		cfg.elf_mode   = s2e()->getConfig()->getBool (getConfigKey() + ".elfMode", false); 
   	s2e()->getDebugStream () << " >> luaLoad: elfMode " << (cfg.elf_mode ? "true" : "false") << '\n'; 
	}
	
	cfg.elf_loaded_sig = 0;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".elfLoadedSig") ) {
		cfg.elf_loaded_sig  = s2e()->getConfig()->getInt(getConfigKey() + ".elfLoadedSig", 0);
   	s2e()->getDebugStream () << " >> luaLoad: elfLoadedSig " << hex(8, cfg.elf_loaded_sig) << '\n'; 
	}
	
	cfg.elf_label_netw_in = 0;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".elfLabelNetwIn") ) {
		cfg.elf_label_netw_in  = s2e()->getConfig()->getBool(getConfigKey() + ".elfLabelNetwIn", false);
   	s2e()->getDebugStream () << " >> luaLoad: elfLabelNetwIn " << hex(8, cfg.elf_label_netw_in) << '\n'; 
	}
	
	cfg.base_addr = LOC_UNKNOWN;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".baseAddr") ) {
		cfg.base_addr  = s2e()->getConfig()->getInt(getConfigKey() + ".baseAddr", LOC_UNKNOWN);
   	s2e()->getDebugStream () << " >> luaLoad: baseAddr " << hex(4, cfg.base_addr) << '\n'; 
	}
	cfg.loc_valid = (cfg.base_addr == LOC_UNKNOWN) ? false : true;
	
	cfg.byte_len = LEN_UNKNOWN;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".byteLen") ) {
		cfg.byte_len   = s2e()->getConfig()->getInt(getConfigKey() + ".byteLen", LEN_UNKNOWN);
   	s2e()->getDebugStream () << " >> luaLoad: byteLen " << cfg.byte_len << '\n'; 
	}
	cfg.len_valid = (cfg.byte_len == LEN_UNKNOWN) ? false : true;
   cfg.end_addr = cfg.base_addr + cfg.byte_len;
	
	cfg.eip_addr = EIP_UNKNOWN;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".eipAddr") ) {
		cfg.eip_addr   = s2e()->getConfig()->getInt(getConfigKey() + ".eipAddr", EIP_UNKNOWN);
   	s2e()->getDebugStream () << " >> luaLoad: eipAddr " << hex(4, cfg.eip_addr) << '\n'; 
	}
   cfg.eip_valid = (cfg.eip_addr == EIP_UNKNOWN) ? false : true;
	
	cfg.sysc = SYSC_UNKNOWN;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".syscallNum") ) {	
		cfg.sysc   = s2e()->getConfig()->getInt(getConfigKey() + ".syscallNum", SYSC_UNKNOWN);
   	s2e()->getDebugStream () << " >> luaLoad: syscallNum " << cfg.sysc << " ("<< hex (1, cfg.sysc) << ")" << '\n'; 
	}
   cfg.sysc_valid = (cfg.sysc == SYSC_UNKNOWN) ? false : true;
	
	cfg.cluster_writes_by = CLUSTER_WRITES_BY;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".clusterWritesBy") ) {	
		cfg.cluster_writes_by = s2e()->getConfig()->getInt(getConfigKey() + ".clusterWritesBy", CLUSTER_WRITES_BY);
   	s2e()->getDebugStream () << " >> luaLoad: clusterWritesBy " << cfg.cluster_writes_by << '\n'; 
	}
	cfg.min_exec_insns    = MIN_EXEC_INSNS;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".minExecInsns") ) {	
		cfg.min_exec_insns    = s2e()->getConfig()->getInt(getConfigKey() + ".minExecInsns",    MIN_EXEC_INSNS);
   	s2e()->getDebugStream () << " >> luaLoad: minExecInsns " << cfg.min_exec_insns << '\n'; 
	}
	cfg.min_exec_bytes    = MIN_EXEC_BYTES;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".minExecBytes") ) {	
		cfg.min_exec_bytes    = s2e()->getConfig()->getInt(getConfigKey() + ".minExecBytes",    MIN_EXEC_BYTES);
   	s2e()->getDebugStream () << " >> luaLoad: minExecBytes " << cfg.min_exec_bytes << '\n'; 
	}
	cfg.max_in_range_insn  = MAX_IN_RANGE_INSNS;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".maxInRangeInsn") ) {	
		cfg.max_in_range_insn  = s2e()->getConfig()->getInt(getConfigKey() + ".maxInRangeInsn",  MAX_IN_RANGE_INSNS);
		s2e()->getDebugStream () << " >> luaLoad: maxInRangeInsn " << cfg.max_in_range_insn << '\n'; 
	}
	cfg.max_out_range_insn = MAX_OUT_RANGE_INSNS;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".maxOutRangeInsn") ) {	
		cfg.max_out_range_insn = s2e()->getConfig()->getInt(getConfigKey() + ".maxOutRangeInsn", MAX_OUT_RANGE_INSNS);
   	s2e()->getDebugStream () << " >> luaLoad: maxOutRangeInsn " << cfg.max_out_range_insn << '\n'; 
	}
	cfg.max_kernel_insn   = MAX_KERNEL_INSNS;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".maxKernelInsn") ) {	
		cfg.max_kernel_insn   = s2e()->getConfig()->getInt(getConfigKey() + ".maxKernelInsn",   MAX_KERNEL_INSNS);
   	s2e()->getDebugStream () << " >> luaLoad: maxKernelInsn " << cfg.max_kernel_insn << '\n'; 
	}
	cfg.max_killable_insn = MAX_KILLABLE_INSNS;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".maxKillableInsn") ) {	
		cfg.max_killable_insn = s2e()->getConfig()->getInt(getConfigKey() + ".maxKillableInsn", MAX_KILLABLE_INSNS);
   	s2e()->getDebugStream () << " >> luaLoad: maxKillableInsn " << cfg.max_killable_insn << '\n'; 
	}
	
	// get list of memory addresses to make symbolic
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".symbVars") ) {
		std::vector<std::string> symb_data;
		symb_data = s2e()->getConfig()->getStringList (getConfigKey() + ".symbVars");  
		for (unsigned i = 0; i < symb_data.size (); i++) {
			cfg.symb_vars.push_back (getUserVar (symb_data, i) );
		}
	}
	
	// get list of memory addresses to watch
	//std::vector<std::string> symb_data;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".monitorVars") ) {
		std::vector<std::string> symb_data;
		symb_data = s2e()->getConfig()->getStringList (getConfigKey() + ".monitorVars");  
		for (unsigned i = 0; i < symb_data.size (); i++) {
			cfg.monitor_vars.push_back (getUserVar (symb_data, i) );
		}
	}
	
	// whether or not to enable following execution past the first system call
	// note that this can be set by the shellcode wrapper via custom insn s2e_dasospreproc_enableMultiple ();
	cfg.allow_multi_sysc   = false;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".multiSysc") ) {
		cfg.allow_multi_sysc   = s2e()->getConfig()->getBool (getConfigKey() + ".multiSysc", false); 
   	s2e()->getDebugStream () << " >> luaLoad: multisysc " << (cfg.allow_multi_sysc ? "true" : "false") << '\n'; 
	}
	
	// whether or not to enable multiple path execution (branching on symb variables)
	cfg.enable_multipath = false;
	if (s2e()->getConfig()->hasKey (getConfigKey() + ".multiPath") ) {
		cfg.enable_multipath = s2e()->getConfig()->getBool (getConfigKey() + ".multiPath", false); 
  	 s2e()->getDebugStream () << " >> luaLoad: multipath " << (cfg.enable_multipath ? "true" : "false") << '\n'; 
	}
   
   // Set a hook for the custom insns
   //custom_instruction_connection = new sigc::connection (s2e()->getCorePlugin()->onCustomInstruction.connect (sigc::mem_fun (*this, &CodeXt::onCustomInstruction) ) );
   custom_instruction_connection = s2e()->getCorePlugin()->onCustomInstruction.connect (sigc::mem_fun (*this, &CodeXt::onCustomInstruction) );

   return;
} // end fn initialize


/* Uses a custom instruction within the binary
 * must #include s2e.h in guest code source 
 * (our custom insns start around line 350 in s2e.h
 * Also must #define CODEXT_OPCODE 0xFA line 49 in Opcodes.h
 */
void CodeXt::onCustomInstruction (S2EExecutionState* state, uint64_t opcode) {
   if (!OPCODE_CHECK(opcode, CODEXT_OPCODE) ) {
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
			if (cfg.base_addr == LOC_UNKNOWN) { // conf.lua takes precedence
         	ok &= state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(cfg.base_addr), 4);
         	cfg.base_addr = cfg.base_addr & 0xffffffff;
			}
         cfg.loc_valid = (cfg.base_addr == LOC_UNKNOWN) ? false : true;
			if (cfg.byte_len == LEN_UNKNOWN) { // conf.lua takes precedence
         	ok &= state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_EBX]), &(cfg.byte_len), 4);
         	cfg.byte_len = cfg.byte_len & 0xffffffff;
			}
         cfg.len_valid = (cfg.byte_len == LEN_UNKNOWN) ? false : true;
			if (cfg.eip_addr == EIP_UNKNOWN) { // conf.lua takes precedence
         	ok &= state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_ECX]), &(cfg.eip_addr), 4);
         	cfg.eip_addr = cfg.eip_addr & 0xffffffff;
			}
         cfg.eip_valid = (cfg.eip_addr == EIP_UNKNOWN) ? false : true;
			if (cfg.sysc == SYSC_UNKNOWN) { // conf.lua takes precedence
				ok &= state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_EDX]), &(cfg.sysc), 4);
         	cfg.sysc = cfg.sysc & 0xffffffff;
			}
         cfg.sysc_valid = (cfg.sysc == SYSC_UNKNOWN) ? false : true;
         cfg.end_addr = cfg.base_addr + cfg.byte_len;
         //ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_CR3]), &(cfg.proc_cr3), 4);
         // S2EExecutionState.h: #define CPU_OFFSET(field) offsetof(CPUX86State, field)
         //cfg.proc_cr3 = cfg.proc_cr3 & 0xffffffff;

         if (!ok) {
            s2e()->getWarningsStream (state) << "!! ERROR: symbolic argument was passed to s2e_op in CodeXt loadmodule" << '\n';
            return;
         }
         onActivateModule (state);
         break;
      case 8:
         //static inline void s2e_codext_init_lua () // uses the lua config to set the options
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
         if (!ok) s2e()->getWarningsStream (state) << "!! ERROR: bad argument was passed to s2e_op: start " << start << " in CodeXt start fuzzing" << '\n';
         ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]), &(end), 4);
         end = end & 0xffffffff;
         if (!ok) s2e()->getWarningsStream (state) << "!! ERROR: bad argument was passed to s2e_op: end " << end << " in CodeXt start fuzzing" << '\n';

         if (!ok) return;
         
         if (start > end) {
            s2e()->getWarningsStream (state) << "!! ERROR: start (" << start << ") > end (" << end << ") is invalid range in CodeXt start fuzzing" << '\n';
            return;
         }
         
         s2e()->getDebugStream () << " >> fuzzInit: datum to be iterated from " << start << " to " << end << '\n'; 

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
            s2e()->getWarningsStream (state) << "!! ERROR: bad argument was passed to s2e_op: start " << std::dec << value << " in CodeXt start fuzzing" << '\n';
            return;
         }
         s2e()->getDebugStream () << " >> fuzzInit: datum forking for value " << std::dec << value << '\n'; 
         
         // the following functions found in S2EExecutionState
         if (state->needToJumpToSymbolic () ) {
            // the state must be symbolic in order to fork
            state->jumpToSymbolic ();
         }
         // in case forking isn't enabled, enable it here
         if (!(state->isForkingEnabled () ) ) {
            state->enableForking ();
         }
         fuzzForkSingle (state, value);
         break;
      case 6 :
         onFini (state);
         break;
      case 7:
         // do multiple system calls
			// s2e_dasospreproc_enableMultiple ();
         cfg.allow_multi_sysc = true;
         break;
      default :
         s2e()->getWarningsStream (state) << "!! ERROR: invalid opcode" << '\n';
   }
   return;
} // end fn onCustomInstruction
   

void CodeXt::onActivateModule (S2EExecutionState* state) {
   if (!cfg.eip_valid) {
      s2e()->getWarningsStream (state) << "Warning: EIP is not set, there may be false positives\n";
   }
   else if (cfg.eip_addr < cfg.base_addr || cfg.eip_addr > cfg.end_addr) {
      s2e()->getWarningsStream (state) << "!! ERROR: EIP " << hex (4, cfg.eip_addr) << " given to CodeXt is not within range " << hex (4, cfg.base_addr) << "-" << hex (4, cfg.end_addr) << '\n';
      terminateStateEarly_wrap (state, std::string ("EIP not in range"), false);
      return;
   }

   cfg.proc_id = (unsigned int) state->getPid ();

   DECLARE_PLUGINSTATE (CodeXtState, state);
	if (cfg.elf_mode) {
		s2e()->getWarningsStream (state) << 
   	//s2e()->getDebugStream () << 
			" >> Recv'ed custom insn for CodeXt on an elf with pid " << cfg.proc_id << ", addr range: " << hex (4, cfg.base_addr) << "-" << hex (4, cfg.end_addr) << " with eip: " << hex (4, cfg.eip_addr) << " buffer length: " << cfg.byte_len << " and syscall number: " << cfg.sysc << '\n';
		plgState->in_ignore_mode = true;

      //state->disableForking ();
      //s2e()->getDebugStream () << " >> Disabled forking" << '\n';
	}
	else {
		s2e()->getWarningsStream (state) << 
		//s2e()->getDebugStream () << 
			" >> Recv'ed custom insn for a CodeXt memory segment within pid " << cfg.proc_id << ", addr range: " << hex (4, cfg.base_addr) << "-" << hex (4, cfg.end_addr) << " with eip: " << hex (4, cfg.eip_addr) << " buffer length: " << cfg.byte_len << " and syscall number: " << cfg.sysc << '\n';
		setHooks (state);
   	cfg.is_loaded = true;
		//plgState->in_ignore_mode = false;
   }

   CorePlugin* plg = s2e()->getCorePlugin ();
   plgState->oTIS_connection = plg->onTranslateInstructionStart.connect (sigc::mem_fun (*this, &CodeXt::onTranslateInstructionStart) );
	
   //s2e()->getDebugStream () << " >> Memory update, cfg is " << sizeof (cfg) << " with " << cfg.successes.size () << " successes, " << cfg.fragments.size () << " fragments, and " << cfg.chunks.size () << " chunks\n";
   // every so often clean up garbage, translated blocks, instructions, etc.
   // plugin uses no pointers, so it should be as clean as possible.
   //tb_flush(env); // didn't seem to retranslate things!
   // by default whenever the state switches the Tbs are flushed.
   // S2EExecutor::flushTb()
   //s2e()->getExecutor()->flushTb ();
   //XXX: flush is required to keep the m_tlbMap cache in sync
   //tlb_flush(env, 1);
   //s2e_flush_tlb_cache
	return;
} // end fn onActivateModule


void CodeXt::setHooks (S2EExecutionState* state) { 
   DECLARE_PLUGINSTATE (CodeXtState, state);
   // hook a per insn callback in here to make the cookie trail
   CorePlugin* plg = s2e()->getCorePlugin ();
   
   plgState->oDMA_connection = plg->onDataMemoryAccess.connect (sigc::mem_fun (*this, &CodeXt::onDataMemoryAccess) );
   plgState->oRA_connection =  plg->onTranslateRegisterAccessEnd.connect (sigc::mem_fun (*this, &CodeXt::onTranslateRegisterAccess) );
   plgState->oDMA_connected = true;
   
   // onTranslateInstructionEnd_RJF is a modified S2E core function that returns the length of the src bytes of instruction translated
   plgState->oTIE_connection = plg->onTranslateInstructionEnd_RJF.connect (sigc::mem_fun (*this, &CodeXt::onTranslateInstructionEnd) );
   plgState->oTIE_connected = true;
   
   plgState->oTBE_connection = plg->onTranslateBlockEnd.connect (sigc::mem_fun (*this, &CodeXt::onTranslateBlockEnd) );
   plgState->oTBE_connected = true;

   plgState->oTBS_connection = plg->onTranslateBlockStart.connect (sigc::mem_fun (*this, &CodeXt::onTranslateBlockStart) );
   plgState->oTBS_connected = true;
	
	// debug
   plgState->oTJS_connection = plg->onTranslateJumpStart.connect (sigc::mem_fun (*this, &CodeXt::onTranslateJumpStart) );
   
   //plgState->oSC_connection_old = plg->onSilentConcretize_old.connect (sigc::mem_fun (*this, &CodeXt::onSilentConcretize_old) );
   plgState->oSC_connection = plg->onSilentConcretize.connect (sigc::mem_fun (*this, &CodeXt::onSilentConcretize) );
   plgState->oSC_connected  = true;
   
   
   plgState->oSF_connection = plg->onStateFork.connect (sigc::mem_fun (*this, &CodeXt::onStateFork) );
	
   plgState->oPC_connection  = plg->onPrivilegeChange.connect    (sigc::mem_fun (*this, &CodeXt::onPrivilegeChange) );
   plgState->oExc_connection = plg->onException.connect          (sigc::mem_fun (*this, &CodeXt::onException) );
   plgState->oPF_connection  = plg->onPageFault.connect          (sigc::mem_fun (*this, &CodeXt::onPageFault) );
   plgState->debugs_connected = true;
   
   // flush the translation block cache when possible change happens
   plgState->flush_tb_on_change = true;

   // init data map, make initial copy
   initDataMap (state);
	
	// this catches after 0th insn (before any translation blocks)
	// mark specific variables as symbolic if trigger has occured, and check if specific variables are concrete or symbolic
	//symbolizeVars (state);

   return;
} // end fn setHooks


// there are certain kill conditions, this is just a nice way to make uniform clean exits
void CodeXt::terminateStateEarly_wrap (S2EExecutionState* state, std::string msg, bool possible_success) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   
   /*// disconnect all the hooks, activateModule might have been called
   if (plgState->oTIE_connected) {
       plgState->oTIE_connection.disconnect ();
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
   }*/
   
   // does terminateStateEarly properly call destructor? If not then need to add in destroy for all the vectors...
   
   // if there were system calls
   if (possible_success && plgState->syscall_cnt > 0) {
      s2e()->getDebugStream () << " >> Possible success terminating reason: " << msg << '\n';  
      // if any were success/matching system calls
      if (anySuccess (plgState->sysc_trace) ) { 
         onSuccess (state);
      }
      else {
         onFragment (state);
      }
      state->dumpX86State (s2e()->getDebugStream () );
		

		s2e()->getDebugStream () << " >> There were " << plgState->labels.size () << " labels." << '\n';
		for (unsigned i = 0; i < plgState->labels.size (); i++) {
			s2e()->getDebugStream () << " >> labels[" << i << "]: " << plgState->labels[i].label << ", expr: " << plgState->labels[i].expr << '\n';
		}
		
		// TODO resolve any non-concrete values for pretty print
		// use CodeXt::dumpX86State ()
      // if this is state[0], then we are in normalize/preprocessor mode, so call fini/output a dump
      if (isInNormalizeMode (state) ) {
         onFiniPreproc (state);
         s2e()->getExecutor()->terminateStateEarly (*state, "EIP reached, preprocessor success");
      }
		if (cfg.elf_mode) {
         s2e()->getExecutor()->terminateStateEarly (*state, "Binary execution ended with successfully finding a system call");
         onFiniElf (state);
		}
      if (anySuccess (plgState->sysc_trace) ) { 
         s2e()->getExecutor()->terminateStateEarly (*state, "Success found, ended this state");
      }
      else {
         s2e()->getExecutor()->terminateStateEarly (*state, "Fragment found, ended this state");
      }
   }
   else { // !possible success || syscall_cnt == 0
      // to help with debug, we may be interested in seeing what bytes were written to by this state
      if (possible_success && plgState->write_trace.writes.size () /*in_range_bytes*/ > 0) {
         s2e()->getDebugStream () << " >> Terminating state w/o syscalls that had " << std::dec << plgState->write_trace.writes.size () << " legitimate writes, outputting its trace and mem_map\n";
         printDataTrace (plgState->write_trace);
         if (plgState->write_trace.in_range_bytes > 0) {
				if (!cfg.elf_mode) {
            	mapWrites (plgState->data_map, plgState->write_trace);
            	printMemMap (plgState->data_map, cfg.base_addr);
				}
         }
      }
      // terminate the state
      s2e()->getExecutor()->terminateStateEarly (*state, msg.c_str () );
      return;
   }
   s2e()->getExecutor()->terminateStateEarly (*state, "!! ERROR: terminateStateEarly_wrap, shouldn't be here");
   return;
} // end fn terminateStateEarly_wrap


void CodeXt::onFiniElf (S2EExecutionState* state) {
   s2e()->getWarningsStream (state) << " >> onFiniElf\n";
   s2e()->getDebugStream () <<  " >> onFiniElf\n";
   if (cfg.successes.size () != 1) {
      s2e()->getDebugStream () <<  "!! ERROR: successes is wrong size (" << cfg.successes.size () << '\n';
      //terminateStateEarly_wrap (state, std::string ("onFiniPreproc successes wrong size"), false);
      s2e()->getExecutor()->terminateStateEarly (*state, "onFiniPreproc successes wrong size");
      return;
   }
   s2e()->getDebugStream () <<  " >>    Printing success " << 0 << '\n';
   printSuccess (cfg.successes[0]);
   s2e()->getDebugStream () <<  " >>    Done printing success " << 0 << '\n';
   
   //terminateStateEarly_wrap (state, std::string ("EIP reached, preprocessor success"), true);
   return;
} // end fn onFiniPreproc


void CodeXt::onFiniPreproc (S2EExecutionState* state) {
   s2e()->getWarningsStream (state) << " >> onFiniPreproc\n";
   s2e()->getDebugStream () <<  " >> onFiniPreproc\n";
   if (cfg.successes.size () != 1) {
      s2e()->getDebugStream () <<  "!! ERROR: successes is wrong size (" << cfg.successes.size () << '\n';
      //terminateStateEarly_wrap (state, std::string ("onFiniPreproc successes wrong size"), false);
      s2e()->getExecutor()->terminateStateEarly (*state, "onFiniPreproc successes wrong size");
      return;
   }
   s2e()->getDebugStream () <<  " >>    Printing success " << 0 << '\n';
   printSuccess (cfg.successes[0]);
   s2e()->getDebugStream () <<  " >>    Done printing success " << 0 << '\n';
   
   dumpPreproc (state);
   
   //terminateStateEarly_wrap (state, std::string ("EIP reached, preprocessor success"), true);
   return;
} // end fn onFiniPreproc


// write a mem dump of the shellcode at the point of the first syscall
// use rawshell, but TODO somehow note EIP
void CodeXt::dumpPreproc (S2EExecutionState* state) {
   uint8_t rawshell[cfg.byte_len];
   // read memory into rawshell
   if (!readMemory (state, cfg.base_addr, rawshell, cfg.byte_len) ) {
      s2e()->getWarningsStream (state) << "!! ERROR: could not read guest memory @" << hex (4, cfg.base_addr) << " to gather rawshell\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read"), true);
      return;
   }
   // write rawshell to file
   std::ofstream raw_out;
   raw_out.open ("preprocessed.rawshell", std::ios::out | std::ios::binary);
   if (!raw_out.is_open () ) {
      s2e()->getWarningsStream (state) << "!! ERROR: could not open shell file\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid file open"), true);
      return;
   }
   s2e()->getWarningsStream (state) << "Writing preprocessed shellcode to file: preprocessed.rawshell\n";
   
   // write to file
   //fwrite (rawshell, sizeof (uint8_t), cfg.byte_len, shell_file);
   raw_out.write ((const char*) rawshell, sizeof (uint8_t) * cfg.byte_len);
   raw_out.close();
   
   return;
} // end fn dumpPreproc


void CodeXt::onFini (S2EExecutionState* state) {
   s2e()->getWarningsStream (state) << " >> Recv'ed onFini custom insn\n";
   s2e()->getDebugStream () <<  " >> Recv'ed onFini custom insn\n"
                               " >> There were " << std::dec << cfg.successes.size () << " successes\n";
   unsigned match_fragment_idx = 0;
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
         
         for (unsigned j = 0; j < s->call_trace.size (); j++) {
            bool exists = false;
            uint64_t eip = s->call_trace[j].addr;
            for (unsigned k = 0; k < eips.size (); k++) {
               if (eip == eips[k]) {
                  exists = true;
               }
            }
            if (!exists) {
               eips.push_back (eip);
            }
         }
         
         s2e()->getDebugStream () <<  " >>    Printing success " << i << '\n';
         printSuccess (cfg.successes[i]);
         s2e()->getDebugStream () <<  " >>    Done printing success " << i << '\n';
      }
      s2e()->getDebugStream () << " >> Done printing successes\n";
      s2e()->getDebugStream () << " >> The success/offset with the highest overlay density is " << odens_max_idx << ", value of " << odens_max << '\n';
      match_fragment_idx = odens_max_idx;
      s2e()->getDebugStream () << " >> The success/offset with the highest average density is " << adens_max_idx << ", value of " << adens_max << '\n';
      s2e()->getDebugStream () << " >> There were " << eips.size () << " different eips: ";
      for (unsigned i = 0; i < eips.size (); i++) {
         s2e()->getDebugStream () << hex (4, eips[i]) << " ";
      }
   } // end if successes
   s2e()->getDebugStream () << '\n';
   
   
   s2e()->getDebugStream () <<  " >> There were " << std::dec << cfg.fragments.size () << " fragments\n";
   // print the fragments see if any match up with successes
   if (cfg.fragments.size () > 0) {
      //float odens_max = 0;
      //unsigned odens_max_idx = 0;
      //float adens_max = 0;
      //unsigned adens_max_idx = 0;
      std::vector<uint64_t> eips;
      for (unsigned i = 0; i < cfg.fragments.size (); i++) {
         Fragment* f = &(cfg.fragments[i]);
         for (unsigned j = 0; j < f->call_trace.size (); j++) {
            bool exists = false;
            uint64_t eip = f->call_trace[j].addr;
            for (unsigned k = 0; k < eips.size (); k++) {
               if (eip == eips[k]) {
                  exists = true;
               }
            }
            if (!exists) {
               eips.push_back (eip);
            }
         }
         s2e()->getDebugStream () <<  " >>    Printing fragment " << i << '\n';
         printFragment (cfg.fragments[i]);
         s2e()->getDebugStream () <<  " >>    Done printing fragment " << i << '\n';
      }
      s2e()->getDebugStream () << " >> Done printing fragments\n";
      //s2e()->getDebugStream () << " >> The success/offset with the highest overlay density is " << odens_max_idx << ", value of " << odens_max << '\n';
      //s2e()->getDebugStream () << " >> The success/offset with the highest average density is " << adens_max_idx << ", value of " << adens_max << '\n';
      s2e()->getDebugStream () << " >> There were " << eips.size () << " different eips: ";
      for (unsigned i = 0; i < eips.size (); i++) {
         s2e()->getDebugStream () << hex (4, eips[i]) << " ";
      }
   } // end if fragments
   s2e()->getDebugStream () << '\n';
   
   if (cfg.successes.size () > 0) {
      // is there any other data to print out? like stored data traces or something?
      createCodeChunks (match_fragment_idx);
      printCodeChunks ();
   }
   
   //terminateStateEarly_wrap (*state, "onFini called, success", true);
   return;
} // end fn onFini


std::string CodeXt::hex (unsigned int bytes, klee::ref<klee::ConstantExpr> const_val) {
		uint64 val = (uint64_t) cast<klee::ConstantExpr>(const_val)->getZExtValue (64);
		return hex (bytes, val);
} // end fn hex klee


//std::ostringstream CodeXt::hex (unsigned int bytes, uint64_t val) {
std::string CodeXt::hex (unsigned int bytes, uint64_t val, bool showbase) {
	uint64_t mask;
	switch (bytes) {
		case 1:
			mask = 0xff;
			break;
		case 2:
			mask = 0xffff;
			break;
		case 3:
			mask = 0xffffff;
			break;
		case 4:
			mask = 0xffffffff;
			break;
		case 5:
			mask = 0xffffffffff;
			break;
		case 6:
			mask = 0xffffffffffff;
			break;
		case 7:
			mask = 0xffffffffffffff;
			break;
		default:
			mask = 0xffffffffffffffff;
	}
	val = val & mask;
	unsigned int width = bytes * 2; 
	std::ostringstream os;
   //std::ostream os;
	os << (showbase ? "0x" : "") << std::hex << std::noshowbase << std::setw (width) << std::setfill ('0') << val << std::dec;
	std::string ret (os.str () );
	//return os; 
	return ret;
} // end fn hex 


std::string CodeXt::bin (unsigned int bits, uint64_t val, bool showbase) {
	std::ostringstream os;
	std::bitset<sizeof (val)> binary (val);
	os << (showbase ? "0b" : "") <<  binary;
	std::string ret (os.str () );
	return ret;
} // end fn bin


// given a unsigned byte, convert to a signed byte
int8_t CodeXt::toSignedByte (uint8_t b) {
   int8_t i = 0;
   // if negative, ie first bit is 1
   if ((b & 0x80) == 0x80) {
      // mask out 1st bit
      b = b & 0x7f;
      i = -128;
   }
   return i + b;
} // end fn toSignedByte


bool CodeXt::isInShell (S2EExecutionState* state, uint64_t pc) {
	if (cfg.elf_mode) {
		if (cfg.proc_id != (unsigned int) state->getPid () )  {
			return false;
		}
		
		if (isInKernMode (pc) ) {
			return false;
		}
		
		/*if (isInLoaderSegment (pc) ) {
			return false;
		}*/
		//DECLARE_PLUGINSTATE (CodeXtState, state);
		/*if (plgState->in_priv_mode) { // this doesn't work bc a oPC 3->0 may occur between oEIS and oEIE, which causes the oEIE to be treated as OOB
			return false;
		}*/
		// if it's not kernel code and the pid matches, then we are within the binary
		// TODO allow the user to specify ranges within a binary like with shellcode
		
		return true;
	}
   if (pc < cfg.base_addr || pc > cfg.end_addr) {
      return false;
   }
   return true;
} // end fn isInShell


// used to test if the call back is happening bc the kernel has interrupted our proccess without being called by our process
// x86 linux memory mapping puts all kernel mode code/data >= 0xc0000000
// otherwise you could look at the kernel task descriptor's state field and see if !TASK_RUNNING
bool CodeXt::isInKernMode (uint64_t pc) {
   if (pc >= 0xc0000000) {
      return true;
   }
   return false;
} // end fn isInKernelMode


bool CodeXt::isInLoaderSegment (uint64_t pc) {
   //return false;
	if (cfg.elf_mode && (pc > 0xb7000000 && pc < 0xb8000000)) {
		return true;
	}
	return false;
} // end fn isInLoaderSegment


// /home/s2e/s2e/dasos/s2e/./s2e/qemu/target-i386/cpu.h:69, there is a set of #defines for the various registers to their code (used by qemu internals).
// You can use that value to translate between the code (0..7) and a string of their name with this array
// Thus X86_REG_NAMES[R_ESP] would return "ESP"
const char * const CodeXt::X86_REG_NAMES[] = {"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "UNK"};


bool CodeXt::isRegABCD (uint8_t reg) {
	//s2e()->getDebugStream () << " >> isRegABCD reg: " << hex (1, reg) << " " << X86_REG_NAMES[reg] << '\n';
	uint8_t reg_abcd_mask = 0b00001111; 
	if ((1 << reg) == ((1 << reg) & reg_abcd_mask) ) {
		//s2e()->getDebugStream () << " true" << '\n';
		return true;
	}
	//s2e()->getDebugStream () << " false" << '\n';
	return false;
} // end fn isRegABCD


uint8_t CodeXt::getRegIndex (std::string reg) {
	switch (reg[2]) {
		case 'X':
			switch (reg[1]) {
				case 'A':
					return 0;
				case 'C':
					return 1;
				case 'D':
					return 2;
				case 'B':
					return 3;
				default:
					return 0;
			}
		case 'P':
			switch (reg[1]) {
				case 'S':
					return 4;
				case 'B':
					return 5;
				default:
					return 0;
			}
		case 'I': 
			switch (reg[1]) {
				case 'S':
					return 6;
				case 'D':
					return 7;
				default:
					return 0;
			}
		default:
			return 0;
	}
} // end fn getRegIndex


uint64_t CodeXt::getRegOffset (uint8_t reg) {
	switch (reg) {
		case 0:
			return CPU_OFFSET (regs[R_EAX]);
		case 1:
			return CPU_OFFSET (regs[R_ECX]);
		case 2:
			return CPU_OFFSET (regs[R_EDX]);
		case 3:
			return CPU_OFFSET (regs[R_EBX]);
		case 4:
			return CPU_OFFSET (regs[R_ESP]);
		case 5:
			return CPU_OFFSET (regs[R_EBP]);
		case 6:
			return CPU_OFFSET (regs[R_ESI]);
		case 7:
			return CPU_OFFSET (regs[R_EDI]);
		default:
			return 0;
	}
	return 0;
} // enf fn getRegOffset

	
std::string CodeXt::getInsnDisasm (S2EExecutionState* state, uint64_t pc) {
	DECLARE_PLUGINSTATE (CodeXtState, state);
	std::string disasm = "";
	bool found = false;
	//s2e()->getDebugStream () << " >> getInsnDisasm pc " << hex (4, pc + cfg.base_addr) << '\n';
   for (int i = plgState->trans_trace.insns.size () - 1; i >= 0 && !found; i--) {
      if (plgState->trans_trace.insns[i].addr == (pc - cfg.base_addr) ) {
         disasm = plgState->trans_trace.insns[i].disasm;
			found = true;
   		//s2e()->getDebugStream () << " >> getInsnDisasm: " << disasm << '\n';
      }
   }
	if (!found) {
      s2e()->getDebugStream () << " >> ERROR getInsnDisasm pc " << hex (4, pc) << " not found" << '\n';
		return "";
	}
	// trim leading whitespace
   while (disasm[0] == ' ') {
   	disasm.erase (0, 1);
   }
   if (disasm.length () == 0) {
      s2e()->getDebugStream () << " >> ERROR getInsnDisasm pc " << hex (4, pc) << " no disasm string" << '\n';
		return "";
   }
	return disasm;
} // end fn getInsnDisasm


// TODO use the bits of the insn to determine the type of addressing used
// Forms of addressing an Intel register are: 1 e?x (all 4B); 2 ?x (lower 2B); 3 ?h (upper 1B of lower 2B); 4 ?l (lowest 1B); 0 error
uint8_t CodeXt::regAddressingType (S2EExecutionState* state, std::string disasm) {
	//s2e()->getDebugStream () << " >> regAddressingType " << disasm << '\n';
	if (isInsnSubstr (state, disasm, "lodsb") ) {
		//s2e()->getDebugStream () << " >> regAddressingType lodsb" << '\n';
		return 4; // same as mov ?l, [esi]
	}
	
	// erase lead whitespace
   while (disasm != "" && disasm[0] == ' ') { 
		disasm.erase (0, 1);
	}
	// find pos of first space (skip command)
	unsigned i = 0;
   while (i < disasm.length () && disasm[i] != ' ') { 
		i++; 
	}
	// i == length || disasm[i] == ' '
	if (i == disasm.length () ) {
		s2e()->getDebugStream () << " >> regAddressingType insn doesn't specify reg" << '\n';
		return 0;
	}
	// disasm[i] == ' '
	i++;
	// disasm[i] == first char of the destination register
	std::string reg = disasm.substr (i, 3); //disasm.length () - i);
	while (reg[reg.length () - 1] == ' ' || reg[reg.length () - 1] == ',') {
		reg.erase (reg.length () - 1, 1);
	}
	//s2e()->getDebugStream () << " >> >> regAddressingType reg suffix: " << reg << '\n';
	if (reg.length () == 2) {
		switch (reg[1]) {
			case 'x':
				return 2;
			case 'h':
				return 3;
			case 'l':
				return 4;
			default:
				return 0;
		}
	}
	else if (reg.length () == 3) {
		if (reg[0] == 'e' && reg[2] == 'x') {
			return 1;
		}
		return 0;
	}
	// else
	s2e()->getDebugStream () << " >> regAddressingType reg wrong length: " << reg << '\n';
	return 0;
} // end fn regAddressingType


bool CodeXt::isInsnSubstr (S2EExecutionState* state, std::string disasm, std::string s) {
	if (disasm.find (s) != std::string::npos) {
		return true;
	}
	return false;
} // end fn isInsnSubstr


bool CodeXt::isInsnSubstr (S2EExecutionState* state, uint64_t pc, std::string s) {
	return isInsnSubstr (state, getInsnDisasm (state, pc), s);
} // end fn isInsnSubstr


bool CodeXt::isTaintDoNothingInsn (S2EExecutionState* state, std::string disasm) {
	// reg insns
	if (isInsnSubstr (state, disasm.substr (0, 4), "loop") ) {
		return true;
	}
	// mem insns
	if (isInsnSubstr (state, disasm.substr (0, 4), "call") ) {
		return true;
	}
	return false;
} // end fn isTaintDoNothingInsn


bool CodeXt::isTaintScrubbingInsn (S2EExecutionState* state, std::string disasm) {
	// reg insns
	if (isInsnSubstr (state, disasm.substr (0, 3), "mov") || isInsnSubstr (state, disasm.substr (0, 3), "pop") || isInsnSubstr (state, disasm.substr (0, 5), "lodsb") ) {
   	//s2e()->getDebugStream () << " >> isTaintScrubbingInsn " << disasm.substr (0, 5) << '\n';
		return true;
	}
	// mem insns
	// push is ok in here, bc we only take actions on writes (so there isn't going to be an erroneous parsing using the src reg as a dest to scrub or anyhing)
	if (isInsnSubstr (state, disasm.substr (0, 3), "mov") || isInsnSubstr (state, disasm.substr (0, 4), "push") || isInsnSubstr (state, disasm.substr (0, 5), "stosb") ) {
   	//s2e()->getDebugStream () << " >> isTaintScrubbingInsn " << disasm.substr (0, 5) << '\n';
		return true;
	}
   //s2e()->getDebugStream () << " >> !isTaintScrubbingInsn " << disasm.substr (0, 5) << '\n';
	return false;
} // end fn isTaintScrubbingInsn


bool CodeXt::isTaint1To1Insn (S2EExecutionState* state, std::string disasm) {
	if (isInsnSubstr (state, disasm.substr (0, 3), "xor") || isInsnSubstr (state, disasm.substr (0, 2), "or") || isInsnSubstr (state, disasm.substr (0, 3), "and") /*|| isInsnSubstr (state, disasm, "not")*/) {
		return true;
	}
	if (isInsnSubstr (state, disasm.substr (0, 3), "mov") ) {
		return true;
	}
	return false;
} // end fn isTaint1To1Insn


bool CodeXt::isInsnMov (std::string disasm) {
   //s2e()->getDebugStream () << " >> isInsnMov.sub(0,3): " << disasm.substr (0, 4) << '\n';
	// Forms of addressing an Intel register are: e?x (all 4B); ?x (lower 2B); ?h (upper 1B of lower 2B); ?l (lowest 1B)
	if (disasm.substr (0, 4) == "mov ") {
		//s2e()->getDebugStream () << " >> >> isMov " << '\n';
		return true;
	}
	return false;
} // end fn isInsnMov


// returns number of bytes of imm value at end of insn
uint8_t CodeXt::isImmSrcInsn (std::vector<struct mem_byte> bytes) {
   //s2e()->getDebugStream () << " >> isImmSrcInsn num_bytes: " << bytes.size () << '\n';
	if (bytes.size () == 0) {
		return 0;
	}
	// https://en.wikibooks.org/wiki/X86_Assembly/Machine_Language_Conversion
   //s2e()->getDebugStream () << " >> isImmSrcInsn bytes[0]: " << hex (1, bytes[0].byte) << '\n';
	// opcodes from: http://ref.x86asm.net/coder32.html
	switch (bytes[0].byte) {
		case 0x34: // xor al imm8
		case 0x0c: // or al imm8
		case 0x24: // and al imm8
		case 0x80: // add/or/adc/sbb/and/sub/xor/cmp r/m8 imm8
		case 0x82: // add/or/adc/sbb/and/sub/xor/cmp r/m8 imm8
		case 0x83: // add/or/adc/sbb/and/sub/xor/cmp r/m16/32 imm8
		case 0xb0: // mov r8 imm8
		case 0xb1: // mov r8 imm8
		case 0xb2: // mov r8 imm8
		case 0xb3: // mov r8 imm8
		case 0xb4: // mov r8 imm8
		case 0xb5: // mov r8 imm8
		case 0xb6: // mov r8 imm8
		case 0xb7: // mov r8 imm8
		case 0xc6: // mov r/m8 imm8
			return 1;
		case 0x35: // xor eax imm16/32
		case 0x0d: // or eax imm16/32
		case 0x25: // and eax imm16/32
			if (bytes.size () == 3) {
				return 2;
			}
			else if (bytes.size () == 5) {
				return 4;
			}
			return 0;
		case 0xb8: // mov r16/32 imm16/32
		case 0xb9: // mov r16/32 imm16/32
		case 0xba: // mov r16/32 imm16/32
		case 0xbb: // mov r16/32 imm16/32
		case 0xbc: // mov r16/32 imm16/32
		case 0xbd: // mov r16/32 imm16/32
		case 0xbe: // mov r16/32 imm16/32
		case 0xbf: // mov r16/32 imm16/32
			if (bytes.size () == 3) {
				return 2;
			}
			else if (bytes.size () == 5) {
				return 4;
			}
			return 0;
		case 0x81: // add/or/adc/sbb/and/sub/xor/cmp r/m16/32 imm16/32
		case 0xc7: // mov r/m16/32 imm16/32
			if (bytes.size () == 4 || bytes.size () == 5) {
				return 2;
			}
			else if (bytes.size () == 6 || bytes.size () == 7) {
				return 4;
			}
			return 0;
		default:
			return 0;
	}
	return 0;
} // end fn isImmSrcInsn


uint32_t CodeXt::getTopOfStack (S2EExecutionState* state) {
	uint64_t esp_addr = 0;
   if (!state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESP]), &(esp_addr), sizeof (uint32_t) ) ) {
		klee::ref<klee::Expr> addr_symb = state->readCpuRegister (CPU_OFFSET (regs[R_ESP]), klee::Expr::Int32);
	   klee::ref<klee::ConstantExpr> const_val;
	   if (!s2e()->getExecutor()->getSolver()->getValue (klee::Query (state->constraints, addr_symb), const_val) ) {
      	s2e()->getDebugStream () << "!! ERROR: getTopOfStack: could not read ESP addr\n";
			return 0;
	  	} 	
		esp_addr = (uint32_t) cast<klee::ConstantExpr>(const_val)->getZExtValue (32);
	}
	//s2e()->getMessagesStream (state) << "Word value inside ESP is: 0x" << hex (4, esp_addr) << '\n';
	//s2e()->getMessagesStream (state) << "Symb expr: " << addr_symb << '\n';
	klee::ref<klee::Expr> symb_val = state->readMemory (esp_addr, klee::Expr::Int32);
	klee::ref<klee::ConstantExpr> const_val;
   if (!s2e()->getExecutor()->getSolver()->getValue (klee::Query (state->constraints, symb_val), const_val) ) {
   	s2e()->getDebugStream () << "!! ERROR: getTopOfStack: could not read value pointed to by ESP\n";
		return 0;
	}
	return (uint32_t) cast<klee::ConstantExpr>(const_val)->getZExtValue (32);
	//s2e()->getMessagesStream (state) << "Word value pointed to by register " << cfg.monitor_vars[i].name << " is: " << hex (4, const_val) << '\n';
	//s2e()->getMessagesStream (state) << "Symb expr: " << symb_val << '\n';
} // end fn getTopOfStack

	
void CodeXt::monitorAddresses (S2EExecutionState* state, std::vector<uint64_t> addresses) {
	for (unsigned i = 0; i < addresses.size (); i++) {
		if (addresses[i] == 0) {
			//s2e()->getDebugStream () << " >> monitorAddresses trans block boundary" << '\n';
		}
		else {
			bool prev_displayed = false;
			for (int j = i; !prev_displayed && j >= 0; j--) {
				if (addresses[i] == addresses[j]) {
					prev_displayed = true;
				}
			}
			if (prev_displayed) {
				s2e()->getDebugStream () << " >> monitorAddresses previously displayed" << '\n';
			}
			else {
				//simplifyAddr (state, addresses[i]); // this should be taken care of by the oSC
				s2e()->getDebugStream () << " >> monitorAddresses[" << hex (4, addresses[i]) << "]: " << read8 (state, addresses[i], false) << '\n';
			}
		}
	}
	return;
} // end fn monitorAddresses
   
   
// grab an X86 context
// TODO, this should read the register symbolically, show its expr, then resolve/store the concrete value
void CodeXt::dumpX86State (S2EExecutionState* state, struct X86State& s) {
   bool ok = 0;
   ok &= state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EAX]), &(s.eax), sizeof (uint32_t) );
   ok &= state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
   ok &= state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
   ok &= state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
   ok &= state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
   ok &= state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDI]), &(s.edi), sizeof (uint32_t) );
   ok &= state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBP]), &(s.ebp), sizeof (uint32_t) );
   ok &= state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESP]), &(s.esp), sizeof (uint32_t) );
   s.eip = state->readCpuState          (CPU_OFFSET (eip),   sizeof (uint32_t)*8 ) & 0xffffffff;
   s.cr2 = state->readCpuState          (CPU_OFFSET (cr[2]), sizeof (uint32_t)*8 ) & 0xffffffff;
   return;
} // end fn dumpX86State

   
void CodeXt::printX86State (struct X86State s) {
   s2e()->getDebugStream () << " eax:" << hex (4, s.eax) << " ebx:" << hex (4, s.ebx) << " ecx:" << hex (4, s.ecx) << " edx:" << hex (4, s.edx) << " esi:" << hex (4, s.esi) << " edi:" << hex (4, s.edi) << " ebp:" << hex (4, s.ebp) << " esp:" << hex (4, s.esp) << " eip:" << hex (4, s.eip) << " cr2:" << hex (4, s.cr2) << std::dec << '\n';
   return;
} // end fn printX86State



// Our tags introduce a lot of non-constant expressions to memory, which makes state->readMemoryConcrete fail
// This fn is based on S2EEexecutionState::readMemoryConcrete (), if a byte isn't constant, then solve for it
bool CodeXt::readMemory (S2EExecutionState* state, uint64_t address, void* buf, uint64_t size) {
	uint8_t* d = (uint8_t*) buf;
   while (size > 0) {
		// s2e::S2EExecutionState:: enum AddressType { VirtualAddress, PhysicalAddress, HostAddress }
      klee::ref<klee::Expr> v = state->readMemory8 (address, state->VirtualAddress);
      if (v.isNull () ) {
   			s2e()->getDebugStream () << "!! ERROR: readMemory: null expression\n";
				return false;
      }
		else if (isa<klee::ConstantExpr> (v) ) {
			*d = (uint8_t) cast<klee::ConstantExpr>(v)->getZExtValue (8);
      }
		else {
			klee::ref<klee::ConstantExpr> const_val;
   		if (!s2e()->getExecutor()->getSolver()->getValue (klee::Query (state->constraints, v), const_val) ) {
   			s2e()->getDebugStream () << "!! ERROR: readMemory: could not solve expression\n";
				return false;
			}
			*d = (uint8_t) cast<klee::ConstantExpr>(const_val)->getZExtValue (8);
		}
      size--;
      d++;
      address++;
   }
   return true; 
} // end fn readMemory


klee::ref<klee::Expr> CodeXt::readMemory8 (S2EExecutionState* state, uint64_t addr) {
	klee::ref<klee::Expr> v = state->readMemory8 (addr, state->VirtualAddress);
   if (v.isNull () ) {
		s2e()->getDebugStream () << "!! ERROR: readMemory8: null expression\n";
		return klee::ref<klee::ConstantExpr> (0); // klee::ConstantExpr::create (0, klee::Expr::Int8);
   }
	return v;
} // end fn readMemory8


klee::ref<klee::Expr> CodeXt::read8 (S2EExecutionState* state, uint64_t pc, bool is_reg) {
	klee::ref<klee::Expr> v;
	if (is_reg) {
		v = state->readCpuRegister (pc, klee::Expr::Int8);
	}
	else {
		v = state->readMemory8 (pc, state->VirtualAddress);
	}
   if (v.isNull () ) {
		s2e()->getDebugStream () << "!! ERROR: read8: null expression\n";
		return klee::ref<klee::ConstantExpr> (0); // klee::ConstantExpr::create (0, klee::Expr::Int8);
   }
	return v;
} // end fn read8

			
void CodeXt::write8 (S2EExecutionState* state, uint64_t pc, klee::ref<klee::Expr> e, bool is_reg) {
	if (e->getWidth() != 8) {
		s2e()->getDebugStream () << " >> >> write8 ERROR width != 8 (" << e->getWidth () << ")" << '\n';
		return;
	}
	if (is_reg) {
		state->writeCpuRegisterRaw (pc, e);
	}
	else {
		if (!state->writeMemory8 (pc, e) ) {
	   	s2e()->getWarningsStream (state)
	   		<< " write8: Can not insert symbolic value"
	      	<< " at " << hex (4, pc)
	      	<< ": can not write to memory\n";
		}
	}
	return;
} // end fn write8


bool CodeXt::isSymb (S2EExecutionState* state, uint32_t address) {
   uint32_t result;
   char buf;
   
   //s2e()->getMessagesStream (state)
   //<< "Testing whether data at " << std::hex << address
   //<< " is symbolic:";
   
   // readMemoryConcrete fails if the value is symbolic
   result = !state->readMemoryConcrete (address, &buf, 1);
   //s2e()->getMessagesStream (state) << (result ? " true" : " false") << '\n';

   return result;
} // end fn isSymbolic


// tests is an address is symbolic, but does so by using segment of code from readMemoryConcrete (used by isSymb [not extended])
// if its symb, then return the symbol expression using symb_val
// if its concrete, then return the value in memory using conc_val
// note that the memory object considers all bits/bytes/addresses symbolic; a concrete byte is just a ConstantExpr
// by returning this values, it safes unnecessary tests and reads if the code goes on to do something like print, or needs the value
bool CodeXt::isSymb_ext (S2EExecutionState* state, uint32_t address, uint8_t& conc_val, klee::ref<klee::Expr>& symb_val) {
   // set some safe default values, clean up for this call
   conc_val = 0;
   symb_val = klee::ref<klee::Expr>(0); // taken from what is used by a failed readMemory () call
   // read a 8b value
   symb_val = read8 (state, address, false);
   // if it's null, there is an error, exit, otherwise
   // if it's not null and not a constant expression, then it's symbolic
   if (symb_val.isNull () || !isa<klee::ConstantExpr> (symb_val) ) {
      return true;
   }
   // if it's not null and is a constant expression, then it's concrete
   // gets the zero extended value in 8 bits of the symbolic formula which is cast as a constant expression
   conc_val = (uint8_t)cast<klee::ConstantExpr>(symb_val)->getZExtValue(8);
	
	//symb_val = s2e()->getExecutor()->simplifyExpr (state, symb_val);
   return false;
} // end fn isSymbolic_extended


// see if addr .. addr+len has been translated
// we really only care if it is in the current block and not executed yet
bool CodeXt::hasBeenTranslated (S2EExecutionState* state, uint64_t pc, uint64_t addr, unsigned len) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   uint64_t n_base = addr - cfg.base_addr;
   uint64_t n_end  = n_base + len - 1;
   uint64_t tb_seq_num = 0;
   for (int i = plgState->trans_trace.insns.size() - 1; i >= 0; i--) {
      // find tb seq_num of most recent translation of PC
      if (pc == plgState->trans_trace.insns[i].addr) {
         tb_seq_num = plgState->trans_trace.insns[i].tb_seq_num;
      }
   }
   //s2e()->getDebugStream () << " >> DEBUG hBT: tb_seq_num: " << std::dec << tb_seq_num << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << " pc: 0x" << pc+cfg.base_addr << " n_base: 0x" << n_base+cfg.base_addr << " n_end: 0x" << n_end+cfg.base_addr << '\n';
   // now look for all insns with the same tb_seq_num, if they are affected by addr, then there has been a same basic block modification and the block needs to be retranslated
   // you could safely further limit it to only those with equal tb_seq_num and greater ti_seq_num (so only those in the current block that have yet to be executed
   for (int i = plgState->trans_trace.insns.size() - 1; i >= 0; i--) {
      if (tb_seq_num == plgState->trans_trace.insns[i].tb_seq_num) {
         uint64_t h_base = plgState->trans_trace.insns[i].addr;
         uint64_t h_end  = plgState->trans_trace.insns[i].addr + plgState->trans_trace.insns[i].len - 1;
         if (!(n_base > h_end || n_end < h_base) ) {
            return true;
         }
      } // end if in same trans block
   }
   return false;
} // end fn hasBeenTranslated


uint64_t CodeXt::getTranslatedPc (S2EExecutionState* state, uint64_t byte_addr) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   for (int i = plgState->trans_trace.insns.size() - 1; i >= 0; i--) {
      // for each translation instance, from most recent back, see if byte addr is within it
      if (byte_addr >= plgState->trans_trace.insns[i].addr && byte_addr <= (plgState->trans_trace.insns[i].addr + plgState->trans_trace.insns[i].len) ) {
         return plgState->trans_trace.insns[i].addr;
      }
   }
	return 0;
} // end fn getTranslatedPc
		
		
// TODO make this use a preset vector of impossible first insn and then search it to see if the given insn exists within it
bool CodeXt::isInsnImpossibleFirst (uint8_t* raw_insn, unsigned raw_insn_len) {
   // the most common impossible first insn is '0 0' which is: add [eax], al
   if (raw_insn_len == 2 && raw_insn[0] == 0 && raw_insn[1] == 0) {
      return true;
   }
   return false;
} // end fn isInsnImpossibleFirst


// finds the next valid insn within a trans_trace starting at index i
unsigned CodeXt::findNextValid (Exec_Trace t, unsigned i) {
   while (i < t.insns.size () && !(t.insns[i].valid) ) {
      i++;
   }
   return i;
} // end fn findNextValid


exec_instance CodeXt::getLastInRangeExec (S2EExecutionState* state) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
	for (int i = plgState->exec_trace.insns.size () - 1; i >= 0; i--) {
		if (plgState->exec_trace.insns[i].in_range) {
			return plgState->exec_trace.insns[i];
		}
	}
	exec_instance last_exec;
	initEventInstance ((event_instance_t&) last_exec);
	return last_exec;
} // end fn getLastInRangeExec


// This serves merely to force reconnect any signals
void CodeXt::onTranslateBlockStart (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc) {
	if (!isInShell (state, pc) || (cfg.elf_mode && isInLoaderSegment (state->getPc () ) ) ) {
		return;
	}
	// could use state->getPc 
   if (isInShell (state, pc) ) {
      DECLARE_PLUGINSTATE (CodeXtState, state);
	   s2e()->getDebugStream () << " >> ------------------------------------------" << '\n';
      s2e()->getDebugStream () << " >> oTBS pc: " << hex (4, pc) << " tb_seq_num: " << std::dec << (plgState->tb_seq_num + 1) << (state->isRunningConcrete ()?" conc":" symb") << '\n'; 
      plgState->tb_seq_num++;
		
		// when we first start up (the first block to translate)
	   if (plgState->in_range_insns == 0) {
			s2e()->getDebugStream () << "First TB dumpX86State:\n";
			state->dumpX86State (s2e()->getDebugStream () );
			s2e()->getDebugStream () << "Word at top of stack: " << hex (4, getTopOfStack (state) ) << '\n';

			// let's avoid unnecessary exceptions (additional symb to conc, kernel time, etc)
			s2e()->getMessagesStream(state) << "Disabling timer interrupt\n";
			state->writeCpuState(CPU_OFFSET(timer_interrupt_disabled), 1, 8);
			s2e()->getMessagesStream(state) << "Disabling all apic interrupt\n";
			state->writeCpuState(CPU_OFFSET(all_apic_interrupts_disabled), 1, 8);
		}

		// if we don't clear these vectors, then upon block retranslation old concretize and reg_trace will linger
		// also we produce these during translation and consume during execution. No execution needs non-self translation productions.
      plgState->concretize_trace.push_back (0);
		plgState->curr_tb_reg_trace.clear ();
		

		symbolizeVars (state); // this will catch the insn_count == 0 symbolizeVars, otherwise all done upon oEIE
		//monitorVars (state); // DEBUG
   }
   return;
} // end fn onTranslateBlockStart

   
// assumes that any system call is at the end of a block
// TBEs are signalled before TIEs, so this catches the syscall at the end of the last block before any changes happen by the next oTIE
// some reg info and such (dumpX86State) isn't updated until the end of the block is reached
void CodeXt::onTranslateBlockEnd (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, bool is_target_valid, uint64_t target_pc) {
	if (!isInShell (state, pc) || (cfg.elf_mode && isInLoaderSegment (state->getPc () ) ) ) {
		return;
	}
   
   if (is_target_valid) {
      s2e()->getDebugStream () << " >> oTBE Target by pc: " << hex (4, pc) << " to pc: " << hex (4, target_pc) << '\n';
      
      DECLARE_PLUGINSTATE (CodeXtState, state);
      plgState->oTBE_nextpc = target_pc;
      //plgState->oTBE_len = tb->lenOfLastInstr;
   }
   
	// just link with onTranslateInsn, where we only hook onExecuteInsn to certain translated insns, this only hooks onExecuteBlock to translated blocks that reach this connection code
   signal->connect (sigc::mem_fun (*this, &CodeXt::onExecuteBlock) );

   return;
} // end fn onTranslateBlockEnd


void CodeXt::onExecuteBlock (S2EExecutionState* state, uint64_t pc) {
	if (!isInShell (state, pc) || (cfg.elf_mode && isInLoaderSegment (state->getPc () ) ) ) {
		return;
	}
   s2e()->getDebugStream () << " >> oEB pc: " << hex (4, pc) << '\n';
   return;
} // end fn onExecuteBlock


void CodeXt::onPrivilegeChange (S2EExecutionState* state, unsigned prev_level, unsigned curr_level) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   if (!(plgState->has_entered_range) ) { 
	   return;
	}
	if (curr_level == 0 && prev_level == 0) {
		return;
	}
   s2e()->getDebugStream () << " >> oPC prev: " << std::dec << prev_level << " curr: " << curr_level << " pid: " << state->getPid () << '\n';
	if (cfg.proc_id != (unsigned int) state->getPid () ) {
		return;
	}
	
	if (prev_level == 3 && curr_level == 0) {
		// we are switching to kernel mode, note: any tainted registers will be clobbered
		// when we first switch, CR3 remains unclobbered, so a switch from our proc to kernel will have our proc's PID
      uint64_t eax_val = 0;
      state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(eax_val), 4);
      eax_val &= 0xffffffff;
   	s2e()->getDebugStream () << " >> oPC going to kernel mode, pc: " << hex (4, state->getPc () ) << " eax: " << hex (4, eax_val) << '\n';
      if (eax_val < 256) {
         uint8_t syscall[2];
         syscall[0] = '\0';
         syscall[1] = '\1';
         readMemory (state, state->getPc (), syscall, 2);
         bool is_sysc = false;
         if (syscall[0] == 0xcd && syscall[1] == 0x80) {
            s2e()->getDebugStream () << " >> oPC from int 0x80" << '\n';
            is_sysc = true;
         }
         else if (syscall[0] == 0x0f) {
            if (syscall[1] == 0x34) {
               s2e()->getDebugStream () << " >> oPC from sysenter" << '\n';
               is_sysc = true;
            }
            else if (syscall[1] == 0x05) {
               s2e()->getDebugStream () << " >> oPC from syscall" << '\n';
               is_sysc = true;
            }
         }
         if (!is_sysc) {
            s2e()->getDebugStream () << " >> oPC from other" << '\n';
         }  
         else { //if (is_sysc) {
            uint64_t ebx_val = 0;
            state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_EBX]), &(ebx_val), 4);
            ebx_val &= 0xffffffff;
            uint64_t ecx_val = 0;
            state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_ECX]), &(ecx_val), 4);
            ecx_val &= 0xffffffff;
            uint64_t edx_val = 0;
            state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_EDX]), &(edx_val), 4);
            edx_val &= 0xffffffff;
            s2e()->getDebugStream () << " >> oPC system call EAX: " << hex (4, eax_val) << "[" << SyscNames[eax_val] << "], EBX: " << hex (4, ebx_val) << ", ECX: " << hex (4, ecx_val) << ", EDX: " << hex (4, edx_val) << '\n';
            if (eax_val == 0x66 && ebx_val == 0x5) {
               s2e()->getDebugStream () << " >> oPC netw about to do an accept" << '\n';
               plgState->get_read_fd = true;
            }
            if (plgState->read_fd != 0 && eax_val == 0x3 && plgState->read_fd == ebx_val) {
               s2e()->getDebugStream () << " >> oPC netw about to do a read on a sock fd" << '\n';
               plgState->read_dst = ecx_val;
               plgState->read_sock = true;
            }
         }
      }
		plgState->in_priv_mode = true;
		return;
	}
	
	if (prev_level == 0 && curr_level == 3) {
		// we are returning to usermode
      uint64_t eax_val = 0;
      state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(eax_val), 4);
      eax_val &= 0xffffffff;
   	s2e()->getDebugStream () << " >> oPC returning to user mode, pc: " << hex (4, state->getPc () ) << " eax: " << hex (4, eax_val) << '\n';
		plgState->in_priv_mode = false;
      if (plgState->get_read_fd) {
         plgState->read_fd = eax_val;
         s2e()->getDebugStream () << " >> oPC netw did accept with sock_fd: " << hex (4, plgState->read_fd) << '\n';
         plgState->get_read_fd = false;
      }
      if (plgState->read_sock) {
         s2e()->getDebugStream () << " >> oPC netw did read of " << eax_val << "B to " << hex (4, plgState->read_dst) << '\n';
         if (cfg.elf_label_netw_in) markNetwInSymb (state, plgState->read_dst, eax_val);
         plgState->read_sock = false;
         plgState->read_dst = 0;
      }
	}
	//symbolizeVars (state); // DEBUG
	//monitorVars (state); // DEBUG
   return;
} // end fn onPrivilegeChange


void CodeXt::onPageFault (S2EExecutionState* state, uint64_t addr, bool iswrite) {
   //if (isInShell (state, addr) ) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   if (plgState->has_entered_range && isInShell (state, addr) ) {  
      s2e()->getDebugStream () << " >> oPF addr: " << hex (4, addr) << " iswrite: " << std::dec << iswrite << '\n';
      s2e()->getDebugStream () << " >> oPF dumpX86State: " << '\n';
      state->dumpX86State (s2e()->getDebugStream () );
   }
   return;
} // end fn onPageFault


void CodeXt::onTranslateJumpStart (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, int jump_type) {
   if (!isInShell (state, pc) ) {
      return;
   }
   s2e()->getDebugStream () << " >> oTJS pc: " << hex (4, pc) << " jump_type: " << std::dec << jump_type << '\n';
   return;
} // end fn onTranslateJumpStart


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
void CodeXt::onException (S2EExecutionState* state, unsigned exception_idx, uint64_t pc) {
   if (isInShell (state, pc) ) {
      s2e()->getDebugStream () << " >> oExc pc: " << hex (4, pc) << " exception_idx: " << exception_idx << " (" << hex (1, exception_idx) << ")\n";
      //state->dumpX86State(s2e()->getDebugStream () );
      // 0x80 128d is softawre interrupt
      if (exception_idx == 0x80) {
         // get eax register
         uint64_t int_num = 0;
         bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &(int_num), 4);
         if (!ok) {
            //s2e()->getWarningsStream (state) << "!! ERROR: symbolic argument was passed to s2e_op in CodeXt onException\n";
            //return;
				klee::ref<klee::Expr> value = state->readCpuRegister (CPU_OFFSET(regs[R_EAX]), klee::Expr::Int32);
				if (!isa <klee::ConstantExpr> (value) ) {
					klee::ref<klee::ConstantExpr> value_const;
					if (!s2e()->getExecutor()->getSolver()->getValue (klee::Query (state->constraints, value), value_const) ) {
						s2e()->getDebugStream () << "!! ERROR: monitorRegister: could not solve expression\n";
						// failure
					}
					int_num = (uint64_t) cast<klee::ConstantExpr>(value_const)->getZExtValue (64);
					//s2e()->getDebugStream () << hex (4, int_num);
					//s2e()->getDebugStream () << " and its symb expr is: " << value << '\n';
				}
				else {
					int_num = (uint64_t) cast<klee::ConstantExpr>(value)->getZExtValue (64);
					//s2e()->getDebugStream () << hex (4, int_num) << '\n';
				}
         }
         int_num = int_num & 0xffffffff;
         s2e()->getDebugStream () << " >> oExc INT 0x80 pc: " << hex (4, pc) << " syscall_num: " << int_num << "(" << hex (4, int_num) << ")\n";
         //state->dumpX86State(s2e()->getDebugStream () );
         // onExc happens before oEI, and if we are here, this state will end before any oEI can be called (fail or success)
         // so the syscall's trans isn't added to the exec_trace, call onExecuteInsnEnd as well!
         onExecuteInsnEnd (state, pc);
         onSyscall (state, pc, int_num);
      }

		//symbolizeVars (state); // DEBUG
		//monitorVars (state); // DEBUG
   }
   return;
} // end fn onException


void CodeXt::onSyscall (S2EExecutionState* state, uint64_t pc, uint32_t sysc_number) {
   uint64_t pid = state->getPid ();
   std::ostream& stream = s2e()->getDebugStream ();
   // since onSyscall isn't hooked until onCustomInstruction, this first condition should never be met
   if (!cfg.is_loaded) {
      stream << "ignore this preload Syscall " << hex (1, sysc_number) << " at addr " << hex (4, pc) << " from pid: " << std::dec << pid << '\n';
      return;
   }
   // if here then loaded, see if not PID
   // the kernel doesn't make system calls, so getPid () is accurate here
   else if (pid != cfg.proc_id) {
      stream << "ignore this postload, non-pid Syscall " << hex (1, sysc_number) << " at addr " << hex (4, pc) << " from pid: " << std::dec << pid << '\n';
      return;
   }
   // if here then loaded and pid matches, see if not within memory address
   else if (!isInShell (state, pc) ) { 
      stream << "ignore this postload, pid, out of mem range Syscall " << hex (1, sysc_number) << " at addr " << hex (4, pc) << " from pid: " << std::dec << pid << '\n';
      return;
   }
   
   // if here then loaded, pid matches, and within address range
   // at this point all paths should result in an terminateStateEarly
 
   
   // TODO make lenOfInsn dynamic (perhaps use tb->lenOfLastInstr if this hook is after the insn vs before it)
   unsigned lenOfInsn = 2; // the only possible insns to be here should be syscall cd80 or sysenter 0f34 which are only 2 bytes
   bool fragment = true;  // by default all that reach here are merely a fragment, they are upgraded to success if meets the other goals (alignment etc)
   // determine if eip matters and if so that it matches goal, determine if sysc_num matters and if so that it matches goal, and if not that it is valid
   if (((cfg.eip_valid && pc == (cfg.eip_addr - lenOfInsn) ) || !cfg.eip_valid) && ((cfg.sysc_valid && sysc_number == cfg.sysc) || (!cfg.sysc_valid && sysc_number <= MAX_SYSCALL_NUM) ) ) {
      fragment = false; 
   }
	

   DECLARE_PLUGINSTATE (CodeXtState, state);
   
   // you could enforce a minimum instruction count for success v fragment here like:
   if (plgState->exec_trace.insns.size() < cfg.min_exec_insns) { 
      terminateStateEarly_wrap (state, std::string ("eliminated this false positive, too few executed insns"), false);
	}
	// you could enforce a minimum byte count for success v fragment here like:
	uint64_t exec_bytes = 0;
	for (unsigned i = 0; i < plgState->exec_trace.insns.size (); i++) {
		exec_bytes += plgState->exec_trace.insns[i].len;
	}
   if (exec_bytes < cfg.min_exec_bytes) { 
      terminateStateEarly_wrap (state, std::string ("eliminated this false positive, too few executed bytes"), false);
	}
	
   
   // All conditions to ignore are ignored, so if it's here, then it must be a either a success or a fragment to consider...
   // but is it a subset or suffix of a previous offset that reached this point?

   // we need to see if the trans_trace is a subset of a previous successful pcs
   bool unique = true;
   if (!isInsnTraceUnique (plgState->exec_trace, (std::vector<struct Fragment_t>) cfg.successes) ) {
      unique = false;
      stream << "!! Unfortunately this execution path is a suffix/subset of a previously found success.";
   }
   if (fragment && !isInsnTraceUnique (plgState->exec_trace, (std::vector<struct Fragment_t>) cfg.fragments) ) {
      unique = false;
      stream << "!! Unfortunately this execution path is a suffix/subset of a previously found fragment.";
   }
   if (!unique) {
      stream << " This path has " << plgState->exec_trace.insns.size () << " instructions, PCs: ";
      // print out all the PCs for each insn
      for (unsigned int i = 0; i < plgState->exec_trace.insns.size (); i++) {
         if (!isInShell (state, plgState->exec_trace.insns[i].addr + cfg.base_addr) ) stream << "[";
         stream << hex (4, (plgState->exec_trace.insns[i].addr + cfg.base_addr) );
         if (!isInShell (state, plgState->exec_trace.insns[i].addr + cfg.base_addr) ) stream << "]";
         stream << " ";
      }
      stream << '\n';
      terminateStateEarly_wrap (state, std::string ("eliminated this false positive, execution path subset of another fragment|success"), false);
      return;
   }
   
   // get the context before the call
   // TODO also get the context after the call
   Syscall sysc;
   sysc.success = !fragment;
   sysc.seq_num = plgState->seq_num;
   sysc.addr    = pc;
   sysc.num     = sysc_number;
   dumpX86State (state, sysc.preState);
   plgState->sysc_trace.push_back (sysc);
   plgState->syscall_cnt++;
   
	// There are various classes of system calls in terms of how they affect our accuracy.
   if (!cfg.allow_multi_sysc) {
      terminateStateEarly_wrap (state, std::string ("non-multi modeling"), true);
   }
   // Certain system calls are indicative of the end this execution path.
   if (isEndOfPath (sysc_number) ) {
      terminateStateEarly_wrap (state, std::string ("end of path class of system call"), true);
   }
   /* Certain system calls do not introduce external information, and we can assume that subsequent execution within the emulator is accurate. They are:
    *  num name 
    * Certain system calls do intoduce external info, and we need to do taint analysis/symbolic execution for subsequent execution. They are:
    *  num name 
    */
   return;
} // end fn onSyscall


   
/* Certain system calls are indicative of the end this execution path. They are:
 *  num name 
 *    1 exit
 *   11 execve
 */
bool CodeXt::isEndOfPath (unsigned num) {
   switch (num) {
      case 1 : // exit
         return true;
         break;
      case 11 : // execve
         return true;
         break;
      default :
         return false;
         break;
   }
   return false;   
} // end fn isEndOfPath


// if the state's id is 0, then this is the 1st state created and the one that the system uses to iterate forks
// ie in exec mode state 0 never reaches activateModule
// however in normalize mode state 0 does reach the activateModule code, thus we can use ID to determine mode
bool CodeXt::isInNormalizeMode (S2EExecutionState* state) {
   if (state->getID () == 0 && !cfg.elf_mode) {
      return true;
   }
   return false;
} // end fn isInNormalizeMode


void CodeXt::onFragment (S2EExecutionState* state) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   s2e()->getDebugStream () << " >> onFragment (syscall found)"
      //"Syscall number 0x" << std::hex << sysc_number << " at addr 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " offset from base: " << std::dec << (pc - cfg.base_addr) << " (should be EIP-" << std::dec << len << ") 
      << " number of exec'ed instructions: " << plgState->exec_trace.insns.size () << ", this is fragment #" << cfg.fragments.size () + 1 << '\n';
   
   // store the fragment
   Fragment f;
   f.is_success = false;
   f.trans_trace = plgState->trans_trace;
   f.exec_trace = plgState->exec_trace;
   f.write_trace = plgState->write_trace;
   f.call_trace = plgState->sysc_trace;
   mapExecs (plgState->code_map, plgState->exec_trace);
   f.code_map = plgState->code_map;
   if (!cfg.elf_mode) { mapWrites (plgState->data_map, plgState->write_trace); }
   f.data_map = plgState->data_map;
   //f.eip_addr = pc + len;
   f.offset = plgState->offset;
   //getSuccessStats (f);
   printFragment (f);
   cfg.fragments.push_back (f);
   
   return;
} // end fn onFragment


bool CodeXt::isInsnTraceUnique (Exec_Trace t, std::vector<struct Fragment_t> f) {
   if (t.insns.size () == 0) {
      // not sure why we'd be given an empty set, but don't save it as a success!
      return false;
   }
   
   //s2e()->getDebugStream () << " >> !! DEBUG isITUnique f.size " << f.size () << " given fragment:\n";
   //printExecTrace (t);
   if (f.size () == 0) {
      return true;
   }
   
   // for each previous path, if this path is a subset of it, then return false
   for (unsigned int i = 0; i < f.size (); i++) {
      //s2e()->getDebugStream () << " >> !! DEBUG isITUnique f[" << i << "]:\n";
      //printExecTrace (f[i].exec_trace);
      if (isExecTraceSubset (t, f[i].exec_trace) ) { //, m) ) {
         //cfg.successes[i].subsets.push_back (plgState->offset);
         return false;
      }
   }
   // if not found within forloop, then return true (this also covers is there are no previous successful paths
   return true;
} // end fn isInsnTraceUnique


// see if any of the states returned a successful run
bool CodeXt::anySuccess (Syscall_Trace t) {
   for (unsigned i = 0; i < t.size (); i++) {
      if (t[i].success) {
         return true;
      }
   }
   return false;
} // end fn anySuccess
   
   
void CodeXt::onSuccess (S2EExecutionState* state) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   s2e()->getDebugStream () << " >> onSuccess (EIP found)"
      //Syscall number 0x" << std::hex << sysc_number << " at addr 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " offset from base: " << std::dec << (pc - cfg.base_addr) << " (should be EIP-" << std::dec << len << ") 
   << " number of exec'ed instructions: " << std::dec << plgState->exec_trace.insns.size () << ", this is success #" << cfg.successes.size () + 1 << '\n';

   // store the success
   Success s;
   s.is_success = true;
   s.trans_trace = plgState->trans_trace;
   s.exec_trace = plgState->exec_trace;
   s.write_trace = plgState->write_trace;
   s.call_trace = plgState->sysc_trace;
   mapExecs (plgState->code_map, plgState->exec_trace);
   s.code_map = plgState->code_map;
   if (!cfg.elf_mode) { mapWrites (plgState->data_map, plgState->write_trace); }
   s.data_map = plgState->data_map;
	mapTaints (state, s.taint_maps);
	
   //s.eip_addr = pc + len;
   s.offset = plgState->offset;
   getSuccessStats (s);
   printSuccess (s);
   cfg.successes.push_back (s);
   
   return;
} // end fn onSuccess


/* success.code_map[i] is a Snapshot
 *  There are two types of densities:
 *   average: the sum of the snapshot densities divided by the number of snapshots; and,
 *   overlay: the number of unique executed bytes across all snapshots divided by the range across all snapshots 
 *            the range is the maximum PC from any snapshot minus the minimum PC in any snapshot. 
 * Average is a good inidcator of well grouped snapshots that might be spaced distantly (shellcode that jumps alot or is broken up across lots of memory); 
 * Overlay is good for shellcode which is clumped together and removes densities impacted by large jmps within the single code block.
 */
void CodeXt::getSuccessStats (Success& s) {
   s.avg_density = 0;
   for (unsigned i = 0; i < s.code_map.snaps.size (); i++) {
      s.avg_density += s.code_map.snaps[i].density;
   }
   s.avg_density = s.avg_density / (float) s.code_map.snaps.size ();
   
   if (s.code_map.snaps.size () == 0) {
      return;
   }
   unsigned code_map_len = s.code_map.snaps[0].mem_bytes.size (); 
   unsigned overlay_min = code_map_len;
   unsigned overlay_max = 0;
   unsigned unique_used_bytes = 0;
   // for each PC within range
   for (unsigned i = 0; i < code_map_len; i++) {
      bool used = false;
      // for each snapshot determine if any used the PC
      for (unsigned j = 0; !used && j < s.code_map.snaps.size (); j++) {
         if (timesUsed (s.code_map.snaps[j], i) > 0 && validated (s.code_map.snaps[j], i) ) {
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


void CodeXt::printFragment (Fragment f) {
   printFragment_t ((struct Fragment_t) f);
   return;
} // end fn printFragment


void CodeXt::printSuccess (Success s) {
   printFragment_t ((struct Fragment_t) s);
   return;
} // end fn printSuccess


void CodeXt::printFragment_t (struct Fragment_t f) {
   if (f.is_success) {
      s2e()->getDebugStream () << " >> Fragment is a SUCCESS\n";
      s2e()->getDebugStream () << " >> Fragment densities, overlay: " << f.overlay_density << "; avg: " << f.avg_density << '\n';
      s2e()->getDebugStream () << '\n';
   }
   printCallTrace (f.call_trace);
   //s2e()->getDebugStream () << " >> Syscall eip: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << f.eip_addr << " offset from base: " << std::dec << (f.eip_addr - cfg.base_addr) <<'\n';
   printTransTrace (f.trans_trace);//, s.code_map);
   s2e()->getDebugStream () << '\n';
   printExecTrace (f.exec_trace);
   printMemMap (f.code_map, cfg.base_addr);
   if (f.write_trace.writes.size () > 0) {
      printDataTrace (f.write_trace);
   }
   if (f.write_trace.in_range_bytes > 0) {
      printMemMap (f.data_map, cfg.base_addr);
   }
   else {
      s2e()->getDebugStream () << " >> No data trace entries\n";
   }
	
   s2e()->getDebugStream () << '\n';
   s2e()->getDebugStream () << " >> Taint maps per label\n";
	for (unsigned i = 0; i < f.taint_maps.size (); i++) {
		printMemMap (f.taint_maps[i], cfg.base_addr);
	}
   return;
} // end fn printFragment_t


Chunk CodeXt::mergeChunks (Chunk before, Chunk after) {
   Chunk c;
   c.reserve (before.size () + after.size () ); // preallocate memory
   c.insert (c.end (), before.begin (), before.end () );
   c.insert (c.end (), after.begin(), after.end() );
   return c;
} // end fn mergeChunks


void CodeXt::createCodeChunks (unsigned match_frag) {
   // make each fragment its own chunk, putting the match_frag at the beginning of the vector
   Chunk match;
   match.push_back (cfg.successes[match_frag]);
   cfg.chunks.push_back (match);
   
   for (unsigned i = 0; i < cfg.successes.size (); i++) {
      if (i != match_frag) {
         Chunk tmp;
         tmp.push_back (cfg.successes[i]);
         cfg.chunks.push_back (tmp);
      }
   }
   for (unsigned i = 0; i < cfg.fragments.size (); i++) {
      Chunk tmp;
      tmp.push_back (cfg.fragments[i]);
      cfg.chunks.push_back (tmp);
   }
   
   bool was_a_merge = true;
   std::vector<Chunk> chunk_merge;
   while (was_a_merge) {
      was_a_merge = false;
      for (unsigned i = 0; i < cfg.chunks.size (); i++) {
         for (unsigned j = 1; j < cfg.chunks.size (); j++) {
            // if the current chunk's last fragment's last insn's addr + len equals the other chunk's first fragment's first insn's addr
            // then i precedes j
            if ((cfg.chunks[i].back().exec_trace.insns.back().addr + cfg.chunks[i].back().exec_trace.insns.back().len) == cfg.chunks[j][0].exec_trace.insns[0].addr) {
               Chunk tmp = mergeChunks (cfg.chunks[i], cfg.chunks[j]);
               cfg.chunks[i] = tmp;
               cfg.chunks.erase (cfg.chunks.begin () + j);
               was_a_merge = true;
            }
            // if the current chunk's first fragment's first insn's addr equals the other chunk's last fragment's last insn's addr + len
            // then j precedes i
            else if (cfg.chunks[i][0].exec_trace.insns[0].addr == (cfg.chunks[j].back().exec_trace.insns.back().addr + cfg.chunks[j].back().exec_trace.insns.back().len) ) {
               Chunk tmp = mergeChunks (cfg.chunks[j], cfg.chunks[i]);
               cfg.chunks[i] = tmp;
               cfg.chunks.erase (cfg.chunks.begin () + j);
               was_a_merge = true;
            }
            
         }
      }
   }
   // group fragments into chunks if end/start addresses are adjacent.
   // any fragment the ends in exit should be the last fragment in its chunk.
   // if any chunk clusters are not immedately adjacent, then they are different chunks
   return;
} // end fn createCodeChunks


void CodeXt::printCodeChunks () {
   s2e()->getDebugStream () << " >> There were " << cfg.chunks.size () << " chunks\n";
   for (unsigned i = 0; i < cfg.chunks.size (); i++) {
      s2e()->getDebugStream () <<  " >>    Printing chunk " << i << '\n';
      printChunk (cfg.chunks[i]);
      s2e()->getDebugStream () <<  " >>    Done printing chunk " << i << '\n';
   }
   s2e()->getDebugStream () << '\n';
   return;
} // end fn printCodeChunks


void CodeXt::printChunk (Chunk c) {
   s2e()->getDebugStream () << " >> There are " << c.size () << " fragments in this chunk\n";
   for (unsigned i = 0; i < c.size (); i++) {
      uint64_t c_start = cfg.byte_len;
      uint64_t c_end = 0;
      // find the minimum and max addr within chunk
      // TODO consider the data used as well
      for (unsigned j = 0; j < c[i].exec_trace.insns.size (); j++) {
         if (c_start > c[i].exec_trace.insns[j].addr) {
            c_start = c[i].exec_trace.insns[j].addr;
         }
         if (c_end < (c[i].exec_trace.insns[j].addr + c[i].exec_trace.insns[j].len) ) {
            c_end = c[i].exec_trace.insns[j].addr + c[i].exec_trace.insns[j].len;
         }
      }
      s2e()->getDebugStream () <<  " >> Chunk fragment " << i << " is " << (c[i].is_success ? "success":"fragment") << " starts at " << hex (4, c_start + cfg.base_addr) << " and ends at 0x" << c_end + cfg.base_addr << ", or " << std::dec << (c_end - c_start) << "B\n";
   }
   return;
} // end fn printCodeChunk


void CodeXt::initDataMap (S2EExecutionState* state) {
	if (cfg.elf_mode) { return; }
	
   DECLARE_PLUGINSTATE (CodeXtState, state);
   // the initial snapshot is just a dump of the observed memory, so we can compare writes later to original values
   // check if the data memory map has been initialized before we try to access it
   if (plgState->data_map.snaps.size () != 0) {
      s2e()->getWarningsStream (state) << "!! ERROR: data memory map could not be initialized\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state that couldn't init data map"), true);
      return;
   }
   
   //s2e()->getDebugStream () <<  " >> DEBUG " << "initDataMap data_map size pre: " << std::dec << plgState->data_map.size () << '\n';
   
   appendSnapshot (plgState->data_map, cfg.byte_len);
   
   //s2e()->getDebugStream () <<  " >> DEBUG " << "initDataMap data_map size post: " << std::dec << plgState->data_map.size () << '\n';
   
   uint8_t data_tmp[cfg.byte_len];
   if (!readMemory (state, cfg.base_addr, data_tmp, cfg.byte_len) ) {
      s2e()->getWarningsStream (state) << "!! ERROR: could not read guest memory @" << hex (4, cfg.base_addr) << " to gather data\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read"), true);
      return;
   }
   // copy from read buffer into mem_map's snapshot
   for (unsigned i = 0; i < cfg.byte_len; i++) {
      byteWrite (plgState->data_map.snaps.back(), i, data_tmp[i]);
   }
   
   
   // in really long 10K+ buffers this really clogs the debug output file
   if (!cfg.has_printed) {
      printMem_raw (data_tmp, cfg.byte_len, cfg.base_addr);
      cfg.has_printed = true;
   }
   
   return;
} // end fn initDataMap


// given a register access event (captured on insn translation), but it into an array we can search later (upon insn execution)
void CodeXt::addRegAccess (uint64_t pc, uint8_t reg, uint64_t offset, uint64_t seq_num, Reg_Access_Trace &trace, bool is_write) {
	// this is the only data input range check, rest of programming assumes sanitzed reg codes
	if (reg > 7) {
		reg = 8;
	}
	data_instance reg_write;
	reg_write.snapshot_idx = 0;    // doesn't matters since the mapping is done after tracing
	reg_write.seq_num = seq_num;   // sequence number of instruction [in order of execution, or the executed insn that made this write]
	reg_write.is_register = reg;   // whether the addr is a register offset, or the nth byte within the array, used in data events
   reg_write.addr = offset;       // offset/pc of insn NOTE: within the snapshot (ie pc - cfg.base_addr)
	reg_write.is_write = is_write;
   reg_write.len = 4;             // num bytes of insn/data
	reg_write.bytes.resize (reg_write.len);
	reg_write.next_pc = 0;         // source address of the influencing symbolic taint/label
   reg_write.other_pc = pc;       // the writer insn address
   reg_write.in_range = false;    // whether it is in the range (ie if the bytes were recorded into the code_map/snapshot
   reg_write.valid = true;        // whether it is an insn worth using in comparisons (ie is not a repeat)
	trace.push_back (reg_write);
	s2e()->getDebugStream () << " >> oTRA pc: " << hex (4, pc) << " " << (is_write ? "write to " : "read from ") << X86_REG_NAMES[reg] << '\n';
	return;
} // end fn addRegAccess


// This catches signals during translation when an instruction will access registers (note that oDMA catches during execution)
// There can be multiple registers per instruction (such as lodsb which updates esi and eax)
void CodeXt::onTranslateRegisterAccess (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t read_mask, uint64_t write_mask, bool isMemoryAccess) {
   // only look at writers from observed memory range that write to within the same memory range
	if (!isInShell (state, pc) || (cfg.elf_mode && isInLoaderSegment (state->getPc () ) ) ) {
		return;
	}
   
   if (state->isRunningExceptionEmulationCode () ) {
      //We do not check what memory the CPU accesses.
      //s2e()->getWarningsStream () << "Running emulation code" << '\n';
      return;
   }

   DECLARE_PLUGINSTATE (CodeXtState, state);
	for (unsigned i = 0; i < 8; i++) {
		uint64_t offset = getRegOffset (i);
		if (read_mask & (1 << i) ) {
			addRegAccess (pc, i, offset, plgState->seq_num, plgState->curr_tb_reg_trace, false);
		}
		if (write_mask & (1 << i) ) {
			addRegAccess (pc, i, offset, plgState->seq_num, plgState->curr_tb_reg_trace, true);
		}
	}
	
	s2e()->getDebugStream () << " >> oTRA pc: " << hex (4, pc) << " read_mask: " << bin (64, read_mask) << " write_mask: " << bin (64, write_mask) << " isMemAccess? " << isMemoryAccess << "\n";
	signal->connect (sigc::mem_fun (*this, &CodeXt::onRegisterAccess) );
	
	return;
} // end fn onTranslateRegisterAccess


// onTranslateRegisterAccess sets an alarm, st when that translated instruction is executed its onRegisterAccess will also be called.
// Can probably drop this, it doesn't do anything other than debug output
void CodeXt::onRegisterAccess (S2EExecutionState* state, uint64_t pc) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
	for (int i = plgState->curr_tb_reg_trace.size () - 1; i >= 0; i--) {
		// TODO present all matches in order so that reads show before writes
		// if this is an element (read/write access) that belongs to the insn's pc we are looking for
		if (plgState->curr_tb_reg_trace[i].other_pc == pc) {
			//s2e()->getDebugStream () << " >> oRA pc: " << hex (4, pc) << " " << (plgState->curr_tb_reg_trace[i].is_write ? "write to  " : "read from ") << X86_REG_NAMES[plgState->curr_tb_reg_trace[i].is_register] << '\n';			
			if (plgState->curr_tb_reg_trace[i].is_write && isRegABCD (plgState->curr_tb_reg_trace[i].is_register) ) {
				s2e()->getDebugStream () << " >> oRA pc: " << hex (4, pc) << " regabcd write to " << X86_REG_NAMES[plgState->curr_tb_reg_trace[i].is_register] << '\n';
			} // end if is_write
		}
	}
	return;
} // end fn onRegisterAccess


// whenever an executing insn reads/writes to memory, this hook is called
void CodeXt::onDataMemoryAccess (S2EExecutionState* state, klee::ref<klee::Expr> guestAddress, klee::ref<klee::Expr> hostAddress, klee::ref<klee::Expr> value, bool isWrite, bool isIO) {
   if (!isa<klee::ConstantExpr> (guestAddress) ) {
      //We do not support symbolic addresses yet...
      s2e()->getWarningsStream (state) << " >> oDMA: symbolic memory addresses are not yet supported" << '\n';
      return;
   }

   // only look at writers (not destinations) from observed memory range
	// you don't want to ignore writes outside of range, bc then we'd miss esp pushes, etc.
   if (!isWrite || !isInShell (state, state->getPc () ) ) {
      return;
   }
	
	if (cfg.elf_mode && isInLoaderSegment (state->getPc () ) ) {
		return;
	}
   
   if (state->isRunningExceptionEmulationCode () ) {
      //We do not check what memory the CPU accesses.
      //s2e()->getWarningsStream () << "Running emulation code" << '\n';
      return;
   }
   
	uint64_t addr = cast<klee::ConstantExpr>(guestAddress)->getZExtValue (64);
	unsigned accessSize;
	uint64_t val;
	
	// TODO why getMinBytes? what if the actual write was more than the minBytes needed? is that possible?
	if (!isa<klee::ConstantExpr>(value) ) {
      //s2e()->getWarningsStream (state) << " >> oDMA: symbolic memory value handler" << '\n';
		// for each byte get a solved value for it
	   klee::ref<klee::ConstantExpr> const_val;
	   s2e()->getExecutor()->getSolver()->getValue (klee::Query (state->constraints, value), const_val); //(state, symb_val, const_val);
		//s2e()->getMessagesStream (state) << "asConstant, expr: " << const_val << '\n';
   	accessSize = klee::Expr::getMinBytesForWidth (const_val->getWidth () );
   	val = cast<klee::ConstantExpr>(const_val)->getZExtValue (64);
      //s2e()->getDebugStream () << "";
   }
	else {
		// All clear, so store this write
   	// data memory map is initialized in module initialization
   	// check here if a new snapshot needs to be appended
   	accessSize = klee::Expr::getMinBytesForWidth (value->getWidth () );
   	val = cast<klee::ConstantExpr>(value)->getZExtValue (64);
	}
	
   
   bool in_range = true;
   
   DECLARE_PLUGINSTATE (CodeXtState, state);
   // now it may be a write from IOB to OOB (like fnstenv)
   if (!isInShell (state, cast<klee::ConstantExpr>(guestAddress)->getZExtValue(64) ) ) {
      in_range = false;/*
      s2e()->getDebugStream () <<
      " >> oDMA OOB Write by seq_num: " << std::dec << plgState->seq_num <<
      " pc: 0x" << std::hex << state->getPc () <<
      ":0x" << std::hex << (state->getPc () - cfg.base_addr) << 
      " to addr: 0x" << std::hex << addr <<
      " len: " << std::dec << accessSize << "B" <<
      " value: ";
      return;*/
      //plgState->last_OOB_write = cast<klee::ConstantExpr>(guestAddress)->getZExtValue(64);
   }
   
   // Detect if there had been a oDMA write within buffer to an already translated insn. If so flush tb buffers or force retranslation
   // there has been change to observed/monitored memory/within buffer, this could be code or potential code
   // if it is within the current basic block we need to retranslate instructions
   if (in_range && plgState->flush_tb_on_change) {
      // catch those that have been translated but not yet executed (or translated and within the same TB as current insn)
      if (hasBeenTranslated (state, (state->getPc () - cfg.base_addr), addr, accessSize) ) {
         s2e()->getDebugStream () << " >> oDMA: Re-translate triggered: Write to previously translated insn! at pc " << hex (4, addr) << '\n';
         // oDMA is signaled before oEI. If you trigger a retranslation, then you'll never get the oEI of the insn that did the oDMA
         // Set a marker that is checked on each oEI, so that it can trigger a retranslation then.
         // It will abort the execution of the current TB. QEMU will retranslate starting from the current instruction pointer on the next fetch/decode iteration.
         plgState->oEI_retranslate = state->getPc ();
      }
      /*else {
         s2e()->getDebugStream () << " >> Benign write\n";
      }*/
   }
   

   data_instance data;
   data.snapshot_idx = 0; //plgState->data_map.size () - 1; // doesn't matters since the mapping is done after tracing
   data.addr = addr - cfg.base_addr;
   data.len = accessSize;
   data.bytes.resize (data.len);
   data.other_pc = state->getPc (); // to keep things uniform, other_pc and next_pc are absolute
   // TODO should data.seq_num be current seq_num + 1, which is seq_num bc it is already set for next insn (bc oDMA happens before oEI, but this must be IOB/valid/etc)
   data.seq_num = plgState->seq_num; // + 1; //getSeqNum (state, data.other_pc); //plgState->seq_num;
   data.in_range = in_range;
   data.valid = true; 
   
   uint8_t buf[sizeof (uint64_t)];
   // the s2e/qemu system just memcpy a uint8_t* of size X into val from ((uint8_t*)&(val) )[0], so to pull it out do the same
   memcpy ((void* ) buf, (void* ) &val, sizeof (uint64_t) );
   for (unsigned i = 0; i < data.len /*sizeof (uint64_t)*/; i++) {      
      //s2e()->getDebugStream () << " >> byte[" << std::dec << i << "]: " << std::setw (2) << std::hex << ((unsigned) buf[i] & 0x000000ff) << " ";
      struct mem_byte byte;
      byte.times_used = 1;
      byte.validated = 0;
      byte.byte = buf[i];
      data.bytes[i] = byte;
   }

   //s2e()->getDebugStream () << '\n';
   if (data.in_range) {
      plgState->write_trace.in_range_bytes += data.len; // TODO not unique bytes!
   }
   plgState->write_trace.writes.push_back (data);
   
	uint64_t esp_addr = 0;
   if (!state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESP]), &(esp_addr), sizeof (uint32_t) ) ) {
      s2e()->getWarningsStream (state) << "!! ERROR: oDMA: could not read ESP addr to gather data\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read"), true);
      return;
	}
   //s2e()->getDebugStream () << " >> oDMA esp: 0x" << std::setw (8) << std::setfill ('0') << std::hex << esp_addr << '\n';
	
	
   s2e()->getDebugStream () << " >> oDMA pc: " << hex (4, data.other_pc) << ":" << hex (4, (data.other_pc - cfg.base_addr) );
	if (addr == (esp_addr - data.len) ) { s2e()->getDebugStream () << " ESP/push"; }
   else if (!data.in_range) { s2e()->getDebugStream () << " OOB"; }
   s2e()->getDebugStream () << 
   " Write by seq_num: " << std::dec << data.seq_num <<
   " to addr: " << hex (4, (data.addr + cfg.base_addr) ) <<
   " len: " << std::dec << data.len << "B" <<
   " value: ";
   for (unsigned i = 0; i < data.len; i++) {
      s2e()->getDebugStream () << " " << hex (1, data.bytes[i].byte, 0) << " ";
   }
   s2e()->getDebugStream () << '\n';
	// if it is a large expression, then simplify it
   for (unsigned i = 0; i < data.len; i++) {
		simplifyAddr (state, data.addr + cfg.base_addr + i, false);
   }
	// oEIE searches the Data_Trace for all instances by an insn with a byte that had been concretized.
	// this enforceTaints to all write destinations
   return;
} // end fn onDataMemoryAccess

		
bool CodeXt::isRetInsn (S2EExecutionState* state, uint64_t pc) {
	if (cast<klee::ConstantExpr>(read8 (state, pc, false) )->getZExtValue (8) == 0xc3) {
		return true;
	}
	return false;	
} // end fn isRetInsn


bool CodeXt::enforceConcreteRetAddr (S2EExecutionState* state) {
	uint32_t esp_addr = 0;
   if (!state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESP]), &(esp_addr), sizeof (uint32_t) ) ) {
		klee::ref<klee::Expr> addr_symb = state->readCpuRegister (CPU_OFFSET (regs[R_ESP]), klee::Expr::Int32);
	   klee::ref<klee::ConstantExpr> const_val;
	   if (!s2e()->getExecutor()->getSolver()->getValue (klee::Query (state->constraints, addr_symb), const_val) ) {
      	s2e()->getDebugStream () << "!! ERROR: enforceConcreteRetAddr: could not read ESP addr" << '\n';
			return false;
	  	} 	
		esp_addr = (uint32_t) cast<klee::ConstantExpr>(const_val)->getZExtValue (32);
	}
	//s2e()->getMessagesStream (state) << "Word value inside ESP is: 0x" << hex (4, esp_addr) << '\n';
	//s2e()->getMessagesStream (state) << "Symb expr: " << addr_symb << '\n';
	klee::ref<klee::Expr> ret_val = state->readMemory (esp_addr, klee::Expr::Int32);
	// if it is a concrete value, then do nothing
   if (isa<klee::ConstantExpr> (ret_val) ) {
   	s2e()->getDebugStream () << " >> enforceConcreteRetAddr: retaddr is concrete " << hex(4, (uint32_t) cast<klee::ConstantExpr>(ret_val)->getZExtValue (32)) << '\n';
   	return false;
   }
	
	klee::ref<klee::ConstantExpr> const_val;
   if (!s2e()->getExecutor()->getSolver()->getValue (klee::Query (state->constraints, ret_val), const_val) ) {
   	s2e()->getDebugStream () << "!! ERROR: enforceConcreteRetAddr: could not read value pointed to by ESP" << '\n';
		return false;
	}
	uint32_t ret_val_conc = cast<klee::ConstantExpr>(const_val)->getZExtValue (32);
	if (!state->writeMemory32 (esp_addr, ret_val_conc, state->VirtualAddress) ) {
   	s2e()->getDebugStream () << "!! ERROR: enforceConcreteRetAddr: could not write concrete value to addr pointed to by ESP" << '\n';
		return false;
	}
   s2e()->getDebugStream () << " >> enforceConcreteRetAddr: changed symbolic retaddr (" << ret_val << ") to concrete retaddr: " << hex (4, ret_val_conc) << '\n';
	return true;
} // end fn enforceConcreteRetAddr


void CodeXt::onTranslateInstructionStart (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc) {
	onTranslateInstruction (signal, state, tb, pc, 0, true);
	return;
} // end fn onTranslateInstructionStart


void CodeXt::onTranslateInstructionEnd (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t nextpc) {
	onTranslateInstruction (signal, state, tb, pc, nextpc, false);
	return;
} // end fn onTranslateInstructionEnd


void CodeXt::onTranslateInstruction (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t nextpc, bool is_start) {
   DECLARE_PLUGINSTATE (CodeXtState, state);

	if (is_start) {  // aka onTranslateInstructionStart
		uint64_t pid = state->getPid ();
		// if we're in elf mode we're hooking oTIS, but waiting for a CR3 change to be is_loaded
		if (cfg.elf_mode) {
			if (!cfg.is_loaded) {
				// we know the CR3 from the wrapper, it's in proc_id
				// when exec is called we can assume the kernel took over, which would use the wrapper's CR3
				// so we should ignore those
			   if (pid == cfg.proc_id) {
					return;
				}
				// eventually an insn with a different CR3 will execute
				// it's a race condition, since other procs could jut in, 
				// perhaps, since we are starting with a suspended VM, we can build a list of existing CR3 to ignore
		   	cfg.proc_id = (unsigned int) pid;
		   	//s2e()->getDebugStream () << " >> Caught CR3 change with pid " << cfg.proc_id << ", addr range: " << hex (4, cfg.base_addr) << "-" << hex (4, cfg.end_addr) << " with eip: " << hex (4, cfg.eip_addr) << " buffer length: " << cfg.byte_len << " and syscall number: " << cfg.sysc << '\n';
		      s2e()->getWarningsStream (state) << " >> Caught CR3 change with pid " << cfg.proc_id << ", addr range: " << hex (4, cfg.base_addr) << "-" << hex (4, cfg.end_addr) << " with eip: " << hex (4, cfg.eip_addr) << " buffer length: " << cfg.byte_len << " and syscall number: " << cfg.sysc << '\n';
		   	cfg.is_loaded = true;
				// still in_ignore_mode!
			} // end if !is_loaded
		
			if (plgState->in_ignore_mode) {
				// if no signature given
				if (cfg.elf_loaded_sig == 0) {
					s2e()->getWarningsStream (state) << " >> No elfLoadedSig given, tracing all prolog" << '\n';
					plgState->in_ignore_mode = false;
					setHooks (state);
				}
				else {
					uint32_t buf;
					readMemory (state, pc, (void *) &buf, 4);
					//s2e()->getDebugStream () << " >> elfLoadedSig @" << hex (4, pc) << " test to " << hex (4, buf) << '\n';
					if (buf == cfg.elf_loaded_sig) {
			   		//s2e()->getDebugStream () << " >> Found elfLoadedSig at: " << hex (4, pc) << '\n';
						s2e()->getWarningsStream (state) << " >> Found elfLoadedSig (" << hex (4, cfg.elf_loaded_sig) << ") at: " << hex (4, pc) << '\n';
						plgState->in_ignore_mode = false;
						setHooks (state);
					}
				}
			} // end if in_ignore_mode
		} // should the above be in oTBS??
		
	   if (!cfg.is_loaded || plgState->in_ignore_mode) {
			return;
		}
		
	   if (pid != cfg.proc_id) {
			return;
		}
		
	   if (!isInShell (state, pc) ) {
	      return;
		}
		
		if (isInLoaderSegment (pc) ) {
			return;
		}
		
	   s2e()->getDebugStream () << " >> ------------------------------------------" << '\n';
		s2e()->getDebugStream () << " >> oTIS pc: " << hex (4, pc) << ":" << hex (4, pc - cfg.base_addr) << (state->isRunningConcrete ()?" conc":" symb") << '\n';
	   signal->connect (sigc::mem_fun (*this, &CodeXt::onExecuteInsnStart) );
		
		//symbolizeVars (state); // DEBUG
		//monitorVars (state); // DEBUG
		return;
	}
	
	// if !is_start, aka onTranslateInstructionEnd
	
   uint64_t len = 0; // TODO insert asserts to make sure that len is set
   if (isInShell (state, pc) ) {
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
         s2e()->getDebugStream () << " >> DEBUG jump tb that had nextpc and len set correctly\n";
      }
      s2e()->getDebugStream () << " >> oTIE pc: " << hex (4, pc) << ":" << hex (4, pc - cfg.base_addr) << " nextpc: " << hex (4, nextpc) << " len: " << std::dec << len << (state->isRunningConcrete ()?" conc":" symb") << '\n';
   }
   
   // put a test on total non-buffer insns and exit if exceeds a certain level
   if (plgState->tot_killable_insns > cfg.max_killable_insn) {
      s2e()->getWarningsStream (state) << " >> NOTE: too many killable insns (tot:" << plgState->tot_killable_insns << ";oob:" << plgState->out_range_insns << ";kern:" << plgState->kernel_insns << ";other:" << plgState->other_procs_insns << "), terminateStateEarly\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state that exec'ed too many killable insns, possible hang or other unexpected error"), true);
      return;
   }
   //if (plgState->tot_killable_insns > (cfg.max_killable_insn - 100) ) s2e()->getWarningsStream (state) << "killable:!(" << plgState->tot_killable_insns << ")\n";
   
   // handle kernel mode insns with a special case
   if (isInKernMode (pc) ) {
      // plgState->has_entered_range: if the call back is activated and has entered range once
      if (plgState->has_entered_range) {
         //s2e()->getDebugStream () << " >> oTIE oTKI\n";
         onTransKernInsns (state, pc);
      }
      return;
   }
   // if it's not a kernel insn, then reset the kernel_insns 
   plgState->kernel_insns = 0;
   
   // s2e's getPid () returns the higest 20b of CR3 (the TLB offset) and can be used to uniquely identify a proc
   // kernel code doesn't change the CR3 unless necessary, as it could cause unnecessary TLB flushing
   // in other words, this doesn't necessarily filter out kernel insns
   // which is why we did the isInKernMode test just a few lines up, so now the pid is valid to use
   uint64_t pid = state->getPid ();
   if (pid != cfg.proc_id) {
      // plgState->has_entered_range: if the call back is activated and has entered range once
      if (plgState->has_entered_range) {
         plgState->other_procs_insns++;
         //NOTE should we not cap other procs?
         plgState->tot_killable_insns++;
         //s2e()->getWarningsStream (state) << "ignore this insn it is not from the pid we want to observe at addr 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " from pid: " << std::dec << pid << " v goal-pid: " << cfg.proc_id << '\n';
      }
      return;
   }
   plgState->other_procs_insns = 0;
   
   // NOTE on the two previous conditionals, the problem is that we want our system to allow for other procs
   // but how do we time our processing out should it hang?
   
   // at this point we are dealing with only the process we want to observe, and there are two cases: isInShell and !isInShell   
   // dont use within_range, do a hard check here
   //if (/*!cfg.elf_mode && */ !isInShell (state, pc) ) {
	if (!isInShell (state, pc) || (cfg.elf_mode && isInLoaderSegment (state->getPc () ) ) ) {
      // plgState->has_entered_range: if the call back is activated and has entered range once
      // ie if not at the code between _init/activateModule and the call to the shellcode
      if (plgState->has_entered_range) {
         // Only OOB same proc (eg library, runover-execution) insns will reach here
         //s2e()->getDebugStream () << " >> oTIE oTOOBI\n";
         onTransOOBInsns (state, tb, pc, len, nextpc);
      }
      return;
   }
   plgState->out_range_insns = 0;
   
   // this is a legit instruction so reset the killable counter
   plgState->tot_killable_insns = 0;
   
   // at this point is NOT in kern mode, PIDs match, is IoB, regardless of has_entered_range value
   //s2e()->getDebugStream () << " >> oTIE oTIOBI\n";
	
   onTransIOBInsns (signal, state, tb, pc, len, nextpc);

   s2e()->getDebugStream () << " >> ------------------------------------------" << '\n';
   return;
} // end fn onTranslateInstruction


void CodeXt::onTransIOBInsns (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t len, uint64_t nextpc) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   if (!plgState->within_range) {
      // if it just entered our module, and it's entered at least once before, then note the re-entry
      if (plgState->has_entered_range) {
         s2e()->getWarningsStream (state) << "@" << hex (4, pc) << ", re-entered buffer range after " << std::dec << plgState->out_range_insns << " OoB insns; last OoB insn @" << hex (4, plgState->trans_trace.insns.back().addr + cfg.base_addr) << std::dec << ", disasm in debug.\n";
         printOOBInsn (state, plgState->trans_trace.insns.back(), plgState->out_range_insns);
      }
      // back from being out of bounds
      plgState->in_range_insns = 0;
   }
   
   //s2e()->getDebugStream () << " >> oTIE oTOOBI: 0\n";
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
   if (plgState->in_range_insns > cfg.max_in_range_insn) {
      s2e()->getWarningsStream (state) << " >> NOTE: Potential inifinite loop or wandering execution exceeding MAX_IN_RANGE, caught at " << hex (4, pc) << '\n';
      terminateStateEarly_wrap (state, std::string ("eliminated this branch which exceeded MAX_IN_RANGE"), true);
      return;
   }
   
   // store translation into trans_trace.

   // get the raw insn bytes from the guest memory
   uint8_t insn_raw[len];
   if (!readMemory (state, pc, insn_raw, len) ) {
		// TODO for each byte convert to concrete and store into insn_raw
      s2e()->getWarningsStream (state) << "!! ERROR: could not read guest memory @" << hex (4, pc) << " to gather ASM insns, oTIOBI\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read"), true);
      return;
   }
   // this is the first insn, so see if it is an impossible first
   if (isFirstInsn && isInsnImpossibleFirst (insn_raw, len) ) {
      s2e()->getWarningsStream (state) << "!! ERROR: this is an impossible first instruction, disasm in debug\n";
      s2e()->getDebugStream () << std::setfill(' ') << std::dec << std::setw (3) << 0 << " " << std::setw(2) << len << "B @" << hex (4, pc) << ":";
      printInsn_raw (insn_raw, len, true);
      s2e()->getDebugStream () << '\n';
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an impossible first instruction"), false);
      return;
   }
   
   // TODO move this elsewhere, check for previous values by searching the trans_trace, leave mem_map for end
   // move trans_trace storage into onExecuteInsnEnd
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
   
   //s2e()->getDebugStream () << " >> oTIE oTOOBI: 3\n";
   // I extended qemu to record the next PC, so ideally this PC should equal the last insn's next_PC
   // TODO at the end of loops it thinks that the next insn is the loop back addr instead of loop.addr + loop.len (the next sequential addr)
   if (plgState->pc_of_next_insn != 0 && plgState->pc_of_next_insn != 0xffffffffffffffff && plgState->pc_of_next_insn != pc) {
      s2e()->getDebugStream () << "!!* pc != prev insn's next_pc; " << hex (4, pc) << " != " << hex (4, plgState->pc_of_next_insn) << '\n';
      // terminateStateEarly_wrap
   }
   plgState->pc_of_next_insn = insn.next_pc;
   // can we can leverage this to see if we're non-self?
   //plgState->pc_of_next_insn_from_last_IoB = insn.next_pc;
	if (!isInShell (state, insn.next_pc) || (cfg.elf_mode && isInLoaderSegment (insn.next_pc) ) ) {
      plgState->expecting_jmp_OOB = true;
   }
   
   //s2e()->getDebugStream () << " >> oTIE oTOOBI: 5\n";
   //s2e()->getDebugStream () << " >> Printing Trans_Trace Instance ";
   plgState->trans_trace.insns.push_back (insn);
   printTransInstance (insn); //, plgState->code_map, /*insn.seq_num /plgState->trans_trace.insns.size () - 1,*/ true);
   
   signal->connect (sigc::mem_fun (*this, &CodeXt::onExecuteInsnEnd) );
	

	//symbolizeVars (state); // DEBUG
	//monitorVars (state); // DEBUG
	
   return;
} // end fn onTransIoBInsns


void CodeXt::onTransOOBInsns (S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, uint64_t len, uint64_t nextpc) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   // if last insn was within_range, ie it just went/jumped to OOB
	if (plgState->within_range) {
      // tell the debug about this, plgState->trans_trace.insns.back() should be a jmp/call
      s2e()->getWarningsStream (state) << " oTOOBI: translating @" << hex (4, pc) << ", left buffer range after " << std::dec << plgState->execed_insns << " IoB exec'ed insns\n";
      if (plgState->execed_insns > 0) {
         s2e()->getWarningsStream (state) << " oTOOBI: got there from last IoB insn " << hex (4, plgState->exec_trace.insns.back().addr + cfg.base_addr) << std::dec << ", disasm in debug.\n";
         printExecInstance (plgState->exec_trace.insns.back() ); //, plgState->code_map, /*plgState->trans_trace.insns.back().snapshot_idx,*/ true);
      // just jumped out of bounds (this is the 1st insn out of range)
      }
      //s2e()->getWarningsStream (state) << '\n';
      plgState->out_range_insns = 0;
		if (cfg.elf_mode && isInLoaderSegment (pc) ) {
			// do nothing, the loader seems to jump unexpectedly
			//plgState->within_range = false;
         s2e()->getWarningsStream (state) << " oTOOBI: it's an elf loader/linker insn.\n";
		}
      else if (!plgState->expecting_jmp_OOB) {
			//if (cfg.elf_mode && isInLoaderSegment (pc) ) {
         	//s2e()->getWarningsStream (state) << " >> NOTE: oTOOBI: !expecting_jmp_OOB we've left our module/shellcode unexpectedly, skipping for now\n";
				//return;
				//}
         s2e()->getWarningsStream (state) << " >> NOTE: oTOOBI: !expecting_jmp_OOB we've left our module/shellcode unexpectedly, terminateStateEarly\n";
         //printOOBDebug (state);
         terminateStateEarly_wrap (state, std::string ("eliminated a state that exec'ed out of module bounds unexpectedly"), true);
         return;
      }
      else { /*if expecting_jmp */
         /* maybe test if isInShell (state, pc) */ 
         // if (plgState->trans_trace.insns.back().next_pc != pc && plgState->trans_trace.insns.back().other_pc != pc) {
         // if it was a jump that we were expecting, then we'd be at a onTBE.
         // onTBE is before onTIE, so nextpc will have been set to plgState->oTBE_nextpc
         // if they don't match, then something else is executing
         // otherwise we'd be at a later insn (eg start of next block) and nextpc wouldn't match
         // or we'd be at a kernel/other proc task switch and its nextpc (even if a TBE) wouldn't match
         // there could be the case where an OOB is jumping back to the last oTBE_nextpc, but then it'd be !within_range, so never here
         if (nextpc != plgState->oTBE_nextpc) {
            s2e()->getWarningsStream (state) << " >> NOTE:  oTOOBI: !oTBE_nextpc this jump destination doesn't match what we were expecting\n"; //, terminateStateEarly\n";
            //printOOBDebug (state);
            // rem the following two lines to make assert soft.
            terminateStateEarly_wrap (state, std::string ("eliminated a state that is at unexpected location"), true);
            return;
         }
      }
   }
   plgState->expecting_jmp_OOB = false;
   plgState->within_range = false;
   plgState->out_range_insns++;
   plgState->tot_killable_insns++;
   // if it ran more than cfg.max_out_range_insn insns
   // then consider it "out of control" and it needs to be terminated.
   // alternatively we could use this to grow the module (observed memory range) should this insn be a legitimate write or jmp
   if (plgState->out_range_insns > cfg.max_out_range_insn) {
      s2e()->getWarningsStream (state) << " >> NOTE:  oTOOBI: cfg.max_out_range_insn we've left our module/shellcode for far too long, terminateStateEarly\n";
      //printOOBDebug (state);
      terminateStateEarly_wrap (state, std::string ("eliminated a state that exec'ed out of module bounds for too long"), true);
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
   else if (plgState->out_range_insns % 1000000 == 0) s2e()->getWarningsStream (state) << "o\'\n';*/
   /* to debug a particular issue 5 Dec 2012 RJF
   if (plgState->out_range_insns > 20000) {
      printOOBInsn (insn, plgState->out_range_insns, state);
   }*/
   // we have all we need from it so do nothing further
   return;
} // end fn onTransOOBInsns


void CodeXt::onTransKernInsns (S2EExecutionState* state, uint64_t pc) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   //s2e()->getWarningsStream (state) << "ignore this insn as it is the kernel interrupting things, but not changing the cr3 value at addr " << hex (4, pc) << '\n';
   plgState->kernel_insns++;
   plgState->tot_killable_insns++;
   // at some point it can go into the kernel, to another proc, and then back to the kernel (CR3 is changed to the value of another proc)
   // thus pid filtering no longer let's us catch OOB insns and our system will not kill a hung observed proc 
   if (plgState->kernel_insns > cfg.max_kernel_insn) {
      s2e()->getWarningsStream (state) << " >> NOTE: we've left our module/shellcode, within kernel now, for far too long, terminateStateEarly\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state that exec'ed out of module bounds, in the kernel, for too long"), true);
      return;
   }
   // otherwise just ignore this insn
   /*if (plgState->kernel_insns < 10) s2e()->getWarningsStream (state) << ",\n";
   else if (plgState->ker*nel_insns* < 100 && plgState->kernel_insns* % 10 == 0) s2e()->getWarni*ngsStream (state) << "k.\n";
   else if (plgState->kernel_insns < 1000 && plgState->kernel_insns % 100 == 0) s2e()->getWarningsStream (state) << "k;\n";
   else if (plgState->kernel_insns < 10000 && plgState->kernel_insns % 1000 == 0) s2e()->getWarningsStream (state) << "k:\n";
   else if (plgState->kernel_insns < 100000 && plgState->kernel_insns % 10000 == 0) s2e()->getWarningsStream (state) << "k!\n";
   else if (plgState->kernel_insns < 1000000 && plgState->kernel_insns % 100000 == 0) s2e()->getWarningsStream (state) << "k'\n";
   else if (plgState->kernel_insns % 1000000 == 0) s2e()->getWarningsStream (state) << "o\'\n';*/
   return;
} // end fn onTransKernInsns


void CodeXt::onExecuteInsnStart (S2EExecutionState* state, uint64_t pc) {
   if (!isInShell (state, pc) ) {
		// you shouldn't get here, bc you should only catch insns that are hooked when translated (oTIOBI)
      s2e()->getDebugStream () << " >> oEIS OOB pc: " << hex (4, pc) << '\n';
      return;
   }
   s2e()->getDebugStream () << " >> ------------------------------------------" << '\n';
   s2e()->getDebugStream () << " >> oEIS pc: " << hex (4, pc) << (state->isRunningConcrete ()?" conc":" symb") << '\n';

		
		if (isRetInsn (state, pc) ) {
			s2e()->getDebugStream () << " >> oEIS pc: " << hex (4, pc) << ":" << hex (4, pc - cfg.base_addr) << " is a ret" << '\n';
			if (enforceConcreteRetAddr (state) ) {
				s2e()->getDebugStream () << " >> oEIS pc: " << hex (4, pc) << ":" << hex (4, pc - cfg.base_addr) << " just fixed a symb ret address" << '\n';
			}
         monitorVars (state); // DEBUG
		}
   DECLARE_PLUGINSTATE (CodeXtState, state);
	// if prev insn involves an oSC, then enforceTaints, retranslate
	if (plgState->last_insn_reg_write_trace.size () > 0 || plgState->last_insn_data_write_trace.writes.size () > 0) { // reg_write is activated by previous oEIE, which be cleared by this insn oEIE
   	if (state->isRunningConcrete () ) {
			s2e()->getDebugStream () << " >> !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << '\n';
      	s2e()->getDebugStream () << " >> oEIS last_insn_write_trace.size > 0 jumpToSymbolicCpp/retranslate triggered at pc " << hex (4, pc) << (state->isRunningConcrete ()?" conc":" symb") << '\n';
			state->jumpToSymbolicCpp (); // we can only write the register if it is in symbolic mode
			// if it was in concrete mode, then the exception will cause this function to exit here
			return;
		}
		// only update the reg oEIS, this will put the value in just before execute and the execution WILL see the new value (per Vitaly)
	   s2e()->getDebugStream () << " >> oEIS enforcingTaints" << '\n'; 
		enforceTaints (state, plgState->last_insn_reg_write_trace, plgState->last_insn_data_write_trace.writes); // this should be the only active taint enforcement call
	}
	
	
	if (cfg.symb_vars.size () > 0) { // if there are any taint labels to begin with
		// if current insn about to be executed scrubs a write destination, then remove any existing taints
		// consider integrating into enforceTaints, s.t. any locations that are to be enforced/tainted that will be scrubbed here, are skipped
		std::string disasm = getInsnDisasm (state, pc);
		if (isTaintScrubbingInsn (state, disasm) ) { 
			for (int i = plgState->curr_tb_reg_trace.size () - 1; i >= 0; i--) {
				// if this is an element (read/write access) that belongs to the insn's pc we are looking for
				if (plgState->curr_tb_reg_trace[i].other_pc == pc && plgState->curr_tb_reg_trace[i].is_write && isRegABCD (plgState->curr_tb_reg_trace[i].is_register) ) {
					s2e()->getDebugStream () << " >> oEIS pc: " << hex (4, pc) << " scrubbable regabcd write to " << X86_REG_NAMES[plgState->curr_tb_reg_trace[i].is_register] << '\n';
					// if this insn removes any existing taint in the register
					unsigned offset = 0;
					unsigned len = 4;
					switch (regAddressingType (state, disasm) ) {
						case 4: // ?l lower of lower 2B
							len = 1;
							break;
						case 3: // ?h higher of lower 2B
							offset = 1;
							len = 1;
							break;
						case 2: // ?x lower 2B
							len = 2;
							break;
						case 1: // e?x
							break;
						default:
							break;
					}
					scrubAddr (state, plgState->curr_tb_reg_trace[i].addr + offset, len, true);
				} // end if there is a scrubbable regabcd write by this insn
			} // end for each tb reg trace entry
		} // end if insn is a taint scrubber
	} // end if any symb_vars

	//symbolizeVars (state); // DEBUG
	//monitorVars (state); // DEBUG
	return;
} // end fn onExecuteInsnStart


// called whenever an insn (that passed checks within onTranslateInsn) is executed
// signal hooked by onTranslateInsn
void CodeXt::onExecuteInsnEnd (S2EExecutionState* state, uint64_t pc) {
   if (!isInShell (state, pc) ) {
      s2e()->getDebugStream () << " >> oEIE OOB pc: " << hex (4, pc) << '\n';
      return;
   }
   s2e()->getDebugStream () << " >> oEIE pc: " << hex (4, pc) << (state->isRunningConcrete ()?" conc":" symb") << '\n';
   
   DECLARE_PLUGINSTATE (CodeXtState, state);
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
      s2e()->getDebugStream () << "!! ERROR: oEIE failed to find a translation, pc: " << hex (4, pc) << '\n';
      terminateStateEarly_wrap (state, std::string ("ERROR: oEB failed to find a translation"), true);
      return;
   }
   
   plgState->exec_trace.in_range_insns++;
   plgState->exec_trace.valid_insns++;
   plgState->exec_trace.last_valid = pc;
   plgState->execed_insns++;

	// we want to stop reinforcing the taints when we finally execute an insn again
	plgState->last_insn_reg_write_trace.clear ();
	plgState->last_insn_data_write_trace.writes.clear ();
	
	// see if this insn originally contained at least 1 byte marked as symbolic
	// if so, then during Translation that byte would have been silently concretized, but this system would have caught an event signal for that and restored that byte's symbolic expr
	if (!isTaintDoNothingInsn (state, e.disasm) ) { // don't bother prop'ing taint for certain insns, like loop writing to ecx
		for (int i = plgState->concretize_trace.size () - 1; i >= 0 && plgState->concretize_trace[i] != 0 /*&& !found*/; i--) {
			uint64_t concretized_addr = plgState->concretize_trace[i];
			if (concretized_addr >= pc && concretized_addr < (pc + e.len) ) {
		      s2e()->getDebugStream () << " >> oEIE pc: " << hex (4, pc) << " had been silently concretized" << " at addr: " << hex (4, concretized_addr) << '\n';
				// for each oRA taint the written registers
				for (int j = plgState->curr_tb_reg_trace.size () - 1; j >= 0; j--) {
					// if the reg write was done by this insns
					if (plgState->curr_tb_reg_trace[j].other_pc == pc && plgState->curr_tb_reg_trace[j].is_write) {
				      s2e()->getDebugStream () << " >> oEIE pc: " << hex (4, pc) << " wrote to reg: " << X86_REG_NAMES[plgState->curr_tb_reg_trace[j].is_register] << '\n';
						// NOTE only prop if it is a write to reg we care about X86_REG_NAMES[] = {"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "UNK"};
						// eg eax, ecx, edx, and ebx; bn esp, esi, edi are problematic for now
						// uint8_t reg_should_propagate_mask = 0b00001111; 
						// if (1 << plgState->curr_tb_reg_trace[j].is_register) == ((1 << plgState->curr_tb_reg_trace[j].is_register) & reg_should_propagate_mask) ) {
						if (isRegABCD (plgState->curr_tb_reg_trace[j].is_register) ) { 
					      s2e()->getDebugStream () << " >> oEIE pc: " << hex (4, pc) << " setting reg_write trigger for next oEIS" << '\n';
							plgState->curr_tb_reg_trace[j].next_pc = concretized_addr; // set the taint src addr
							plgState->last_insn_reg_write_trace.push_back (plgState->curr_tb_reg_trace[j]);
						}
						// need to purge the reg_trace and concretize_trace since all pending translations are tossed out. <- do this on every oTBS
					} // end if reg access happened by this insn and was a write
				} // end for each reg access that happened in this tb
				bool found = false;
				bool keep_looking = false;
				for (int j = plgState->write_trace.writes.size () - 1; (keep_looking || !found) && j >= 0; j--) {
					// for curr tb data trace writes by this insn
					if (plgState->write_trace.writes[j].other_pc == pc && plgState->write_trace.writes[j].is_write) {
						keep_looking = true;
						found = true;
				      s2e()->getDebugStream () << " >> oEIE pc: " << hex (4, pc) << " wrote " << plgState->write_trace.writes[j].len << "B to addr: " << hex (4, plgState->write_trace.writes[j].other_pc) << '\n';
					   s2e()->getDebugStream () << " >> oEIE pc: " << hex (4, pc) << " setting data_write trigger for next oEIS" << '\n';
						plgState->write_trace.writes[j].next_pc = concretized_addr; // set the taint src addr
						plgState->last_insn_data_write_trace.writes.push_back (plgState->write_trace.writes[j]); 
					}
					// end backwards search within write_trace after most-temporaly-recent cluster of contiguous writes by pc ends
					else {
						keep_looking = false;
					}
				} // end for each data access that happened in this tb
			} // end if concretized happened in this insn
		} // end for each concretized trace that happened in this tb
	} // end if !isTaintDoNothingInsn
	
   // get bytes from memory and compare to trans' bytes
   uint8_t insn_raw[e.len];
	for (unsigned i = 0; i < e.len; i++) {
   	if (!readMemory (state, pc + i, &(insn_raw[i]), 1) ) {
      	//s2e()->getWarningsStream (state) << " >> WARNING: this byte is symbolic, code doesn't exist to convert to a valid concrete value @" << hex (4, pc) << " needed to gather ASM insns, oEI\n";
      	s2e()->getWarningsStream (state) << "!! ERROR: could not read guest memory @0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << pc << " to gather ASM insns, oEI\n";
      	terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read"), true);
      	return;
   	}
		// else is symbolic, so try to make a concrete example of the symb expr
		else if (e.bytes[i].byte != insn_raw[i]) {
         s2e()->getDebugStream () << " >> WARNING: oEIE bytes in mem (executed) do not match bytes when translated, pc: " << hex (4, pc) << " trans: ";
         for (unsigned j = 0; j < e.len; j++) {
            s2e()->getDebugStream () << hex (1, e.bytes[j].byte, 0);
         }
         s2e()->getDebugStream () << " (" << e.disasm << ") raw: ";
         for (unsigned j = 0; j < e.len; j++) {
            s2e()->getDebugStream () << hex (1, insn_raw[j], 0);
         }
         s2e()->getDebugStream () << " (" << getDisasmSingle (insn_raw, e.len) << "), was there a same-block modification that the system missed?\n";
		}
	}
   
   // impossible first insns are filtered out in oTIE
   
   handleIfFPU (state, e);
      
   plgState->exec_trace.insns.push_back (e);
   printExecInstance (e);
      
	// mark specific variables as symbolic if trigger has occured, and check if specific variables are concrete or symbolic
	symbolizeVars (state); // this is the most vital call to this function
	//monitorVars (state);
	if (cfg.monitor_vars.size () > 0) { monitorAddresses (state, plgState->concretize_trace); } // DEBUG
	
	if (0) {
      // branch testing. &x is -13(%ebp) (or ebp-0xd)
      //if (plgState->exec_trace.in_range_insns > 20 && e.bytes[0].byte == 0x41) { 
      // make sure we are turning x symbolic at the correct place, too early and it might get clobbered and the addr become marked as concrete
      // look for a inc ecx just after a xor ecx,ecx
      if (plgState->exec_trace.insns.size () >= 2 &&  e.bytes[0].byte == 0x41 && plgState->exec_trace.insns[plgState->exec_trace.insns.size () - 2].bytes[0].byte == 0x31) {
      //if (pc >= (cfg.base_addr + 0x3e) ) { 
         uint32_t x2_addr;
         if (!(state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBP]), &(x2_addr), sizeof (uint32_t) ) ) ) {
            s2e()->getMessagesStream (state) << "Error reading EBP\n";
         }
         x2_addr -= 0xd; //-13
         if (!(plgState->x_is_symb) ) {
            // make that addr symb
            // TODO use other markSymb prototype: 
				// markSymb (state, x2_addr, "x");
            plgState->x_is_symb = true;
         }
         uint8_t conc_val;
         klee::ref<klee::Expr> symb_val;
         // is x symb?
         if (isSymb_ext (state, x2_addr, conc_val, symb_val) ) {
            s2e()->getMessagesStream (state) << "X (" << hex (4, x2_addr) << ") is symbolic, expr: " << symb_val << '\n';
         }
         else {
            s2e()->getMessagesStream (state) << "X (" << hex (4, x2_addr) << ") is concrete, val:  " << hex (1, conc_val) << "; expr: " << symb_val << '\n';
         }
      }
   }
	
   // if the last oDMA was a write that requires a retranslation, then match its pc to this pc and retranslate the block
   if (plgState->oEI_retranslate == pc) {
   	s2e()->getDebugStream () << " >> !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << '\n';
      s2e()->getDebugStream () << " >> oEIE forced retranslate triggered (probably due to same basic block self-modification) at pc " << hex (4, pc) << (state->isRunningConcrete ()?" conc":" symb") << '\n';
      plgState->oEI_retranslate = 0;

      // this causes current execution loop to exit (this may be exception 239), and then pick back up at the pc (which happens to be the next insn; perfect!). By pick back up I mean that it retranslates from PC and then executes that retranslation.
      // https://groups.google.com/forum/?fromgroups=#!topic/s2e-dev/1L9ABYSlw0w
      // You can throw CpuExitException() from your plugin code. It will abort the execution of the current TB. QEMU will retranslate starting from the current instruction pointer on the next fetch/decode iteration. -Vitaly
		//state->jumpToSymbolicCpp (); //SymbI
		// state->jumpTpSymbolicCpp sets state->m_startSymbexAtPc to the insn after this (EIP) and then a throw CpuExitException ()
		//https://groups.google.com/forum/#!searchin/s2e-dev/force$20symbolic/s2e-dev/zMvoqfd67Gk/J_dOhFfSRR0J
		
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

   s2e()->getDebugStream () << " >> ------------------------------------------" << '\n';
   return;
} // end fn onExecuteInsnEnd


void CodeXt::handleIfFPU (S2EExecutionState* state, exec_instance e) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   if (e.bytes[0].byte >= 0xd8 && e.bytes[0].byte <= 0xdf) {
      //bool was_fpustenv = false;
      // if fnstenv D9 / 6 ; possibly also fstenv 9B D9 / 6 (and fsav fnsav/fxsav)
      // look at i386-translate.c:5692-ish
      // http://www.posix.nl/linuxassembly/nasmdochtml/nasmdoca.html
      /* Note that there may be other FPU store env variations:
       * look into fstenv, fstpt, fnsave, etc. */
      if (e.bytes.size () == 4 && e.bytes[0].byte == 0xd9) {
         // TODO needs further honing to only capture FPU stenv insns
         // this insn should write a FPU exception struct to the given address, but the struct isn't handled correctly (the last fpu pc not set upon any fpu insn
         //s2e()->getDebugStream () << " >> oEI handling FPU stenv pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << e.addr + cfg.base_addr << '\n';
         
         
         // TODO instead of using findWriteAddr via data trace, decode the bytes from Effective Address Encoding: ModR/M and SIB
         // NOTE until fixed this doesn't work if fpu insn is the first insn
         // otherwise oEI happens after oDMA, so we can find this insn's write addr within the data_trace 
         // (should be the most recent write)
         // look into the write trace and find the last write (eg the write.other_pc that matches e.addr)
         uint64_t write_addr = 0;
         if ((write_addr = findWriteAddr (e.addr + cfg.base_addr, plgState->write_trace) ) == 0) {
            s2e()->getWarningsStream (state) << "!! ERROR: could not find write address\n";
            terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid findWriteAddr"), true);
         }
         // adjust to write where the last_fpu_pc is expected to be (offset of last fpu pc within the fpu exception struct)
         
         write_addr += 0xc;
         s2e()->getDebugStream () << " >> oEI handling FPU stenv pc: " << hex (4, e.addr + cfg.base_addr) <<  " writing last_fpu_pc: " << hex (4, plgState->last_fpu_pc) << " to target: " << hex (4, write_addr) << '\n'; // (which prob should equal esp i fyou need to double check)\n";
         //state->dumpX86State (s2e()->getDebugStream () );
         if (!state->writeMemoryConcrete(write_addr, &(plgState->last_fpu_pc), sizeof (plgState->last_fpu_pc) ) ) {
            s2e()->getWarningsStream (state) << "!! ERROR: could not write guest memory @" << hex (4, write_addr) << " to store last_fpu_pc\n";
            terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid write"), true);
            return;
         }
      } // end if fpu stenv
      //if (!was_fpustenv) {
      s2e()->getDebugStream () << " >> oEI handling FPU insn pc: " << hex (4, e.addr + cfg.base_addr) << '\n';
      // store the pc incase fnstenv is called
      plgState->last_fpu_pc = e.addr + cfg.base_addr;
      //}
   } // end if FPU insn
   return;
} // end fn handleIfFPU


struct symb_var_t CodeXt::getUserVar (std::vector<std::string> symb_data, unsigned& i) { 
	struct symb_var_t symb_var;
	symb_var.name = symb_data[i]; i++;                 // name of symb var 
	if (symb_var.name[0] == '_') {
		symb_var.addr = getRegOffset (getRegIndex (symb_var.name.substr (1,3) ) ); i++;
	}
	else {
		symb_var.addr = atoi (symb_data[i].c_str() ); i++; // offset in bytes from start of shellcode loaded
	}
	symb_var.len  = atoi (symb_data[i].c_str() ); i++; // length in num bytes of variable
	symb_var.when = atoi (symb_data[i].c_str() );      // at which insn to make symbolic
	symb_var.marked = 0;
	symb_var.exprs.reserve (symb_var.len);
	s2e()->getDebugStream () << " >> luaLoad: symb/monitor_vars[" << int (i/4) << "]: " << symb_var.name << " at " << symb_var.addr << " for " << symb_var.len << "B after insn " << symb_var.when << '\n'; 
	return symb_var;
} // end fn getUserVar


void CodeXt::symbolizeVars (S2EExecutionState* state) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   //uint8_t conc_val;
   //klee::ref<klee::Expr> symb_val;
	//s2e()->getMessagesStream (state) << cfg.symb_vars[i].name << " (" << hex (4, cfg.base_addr + cfg.symb_vars[i].addr) << ") ";
	for (unsigned i = 0; i < cfg.symb_vars.size (); i++) {
		if (plgState->execed_insns >= cfg.symb_vars[i].when) {
			bool monitor_printed = 1;
			// TODO see if this works with reg names
			if (!cfg.symb_vars[i].marked && !isSymb (state, cfg.base_addr + cfg.symb_vars[i].addr) ) {
	         markSymb (state, cfg.symb_vars[i]);
				cfg.symb_vars[i].marked = 1;
            monitor_printed = 0;
			}
			if (!monitor_printed && cfg.symb_vars[i].name[0] == '_') { // register
				monitorRegister (state, cfg.symb_vars[i]);
				monitor_printed = 1;
			}
			// else it's not a register, so it's a memory address
			// for each byte in monitor var
			for (unsigned j = 0; !monitor_printed && j < cfg.symb_vars[i].len; j++) {
				monitorMemByte (state, cfg.symb_vars[i], j);
			}
		} // end if doing something for this var
	} // end for each var
	return;
} // end fn symbolizeVars


void CodeXt::monitorVars (S2EExecutionState* state) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   //uint8_t conc_val;
   //klee::ref<klee::Expr> symb_val;
	for (unsigned i = 0; i < cfg.monitor_vars.size (); i++) {
		if (plgState->execed_insns >= cfg.monitor_vars[i].when) {
			bool monitor_printed = 0;
			if (cfg.monitor_vars[i].name[0] == '_') { // register
				monitorRegister (state, cfg.monitor_vars[i]);
				monitor_printed = 1;
			}
			// else it's not a register, so it's a memory address
			// for each byte in monitor var
			for (unsigned j = 0; !monitor_printed && j < cfg.monitor_vars[i].len; j++) {
				monitorMemByte (state, cfg.monitor_vars[i], j);
			}
		} // end if doing something for this var
	} // end for each var
	return;
}// end fn monitorVars


void CodeXt::monitorMemByte (S2EExecutionState* state, struct symb_var_t s, unsigned offset) {	
	// get 8b value in memory
	uint8_t value_conc = 0;
   s2e()->getDebugStream () << " >> monitorMemByte " << s.name << "[" << offset << "] byte value is ";
	uint64_t monitor_addr = cfg.base_addr + s.addr + offset;
	klee::ref<klee::Expr> value = read8 (state, monitor_addr, false);
   if (!isa<klee::ConstantExpr>(value) ) {
		klee::ref<klee::ConstantExpr> value_const;
		if (!s2e()->getExecutor()->getSolver()->getValue (klee::Query (state->constraints, value), value_const) ) {
			s2e()->getDebugStream () << "!! ERROR: CodeXt::monitorMemByte: could not solve expression\n";
			// failure
		}
		value_conc = (uint8_t) cast<klee::ConstantExpr>(value_const)->getZExtValue (8);
		s2e()->getDebugStream () << hex (1, value_conc);
		s2e()->getDebugStream () << " and its symb expr is: " << value << '\n';
   }
	else {
   	value_conc = (uint8_t) cast<klee::ConstantExpr>(value)->getZExtValue (8);
		s2e()->getDebugStream () << hex (1, value_conc) << '\n';
	}
	return;
} // end fn monitorMemByte


void CodeXt::monitorRegister (S2EExecutionState* state, struct symb_var_t s) {
	// there are two parts:
	//   1) the 32b value within the register
	//   2) the 32b pointed to by the value within the register
	// some regs are more likely to be pointers than others
	// {"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "UNK"}; 
	
	// get 32b value within register
	uint32_t value_conc = 0;
	klee::ref<klee::Expr> value;
   s2e()->getDebugStream () << " >> monitorRegister " << s.name << " word value inside is ";
	
	value = state->readCpuRegister (s.addr, klee::Expr::Int32);
	if (!isa <klee::ConstantExpr> (value) ) {
		klee::ref<klee::ConstantExpr> value_const;
		if (!s2e()->getExecutor()->getSolver()->getValue (klee::Query (state->constraints, value), value_const) ) {
			s2e()->getDebugStream () << "!! ERROR: CodeXt::monitorRegister: could not solve expression\n";
			// failure
		}
		value_conc = (uint32_t) cast<klee::ConstantExpr>(value_const)->getZExtValue (32);
		s2e()->getDebugStream () << hex (4, value_conc);
		s2e()->getDebugStream () << " and its symb expr is: " << value << '\n';
	}
	else {
		value_conc = (uint32_t) cast<klee::ConstantExpr>(value)->getZExtValue (32);
		s2e()->getDebugStream () << hex (4, value_conc) << '\n';
	}

	// pointers typically: "ESP", "EBP", "ESI", "EDI"
	if (s.name[3] == 'P') { //} || s.name[3] == 'I') {
		// DEBUG, value_conc is an address, print the word at its location
		value = state->readMemory (value_conc, klee::Expr::Int32);
		klee::ref<klee::ConstantExpr> value_const;
		if (!s2e()->getExecutor()->getSolver()->getValue (klee::Query (state->constraints, value), value_const) ) {
		 	// failure
		}
		value_conc = (uint32_t) cast<klee::ConstantExpr>(value_const)->getZExtValue (32);
		// raw no if symb/conc check for debug
		s2e()->getDebugStream () << "Word value pointed to by register " << s.name << " is: " << hex (4, value_conc) << '\n';
		s2e()->getDebugStream () << "Symb expr: " << value << '\n';
	}
} // end fn monitorRegister


void CodeXt::markNetwInSymb (S2EExecutionState* state, uint32_t buf_addr, uint32_t buf_len) {
   struct symb_var_t svar;
   svar.name = "netwIn";
	svar.addr = buf_addr;
	svar.len = buf_len;
	svar.when = 0;
	svar.marked = false;
   cfg.symb_vars.push_back (svar);
   symbolizeVars (state);
   return;
} // end fn markNetwInSymb


void CodeXt::markSymb (S2EExecutionState* state, struct symb_var_t svar) {
	// find array index of this symb variable within symb_vars
	// just check address against 0th addr of symb_vars since they should match at this point
	uint64_t symb_var_idx = 0;
	for (unsigned i = 0; i < cfg.symb_vars.size (); i++) {
		if (svar.addr == cfg.symb_vars[i].addr) {
			symb_var_idx = i;
			i = cfg.symb_vars.size ();
		}
	}
   s2e()->getDebugStream () << " >> markSymb: using symb_var_idx: " << symb_var_idx << '\n';
	cfg.symb_vars[symb_var_idx].exprs.resize (svar.len);
	cfg.symb_vars[symb_var_idx].labels.resize (svar.len);
   s2e()->getDebugStream () << " >> markSymb: length: " << svar.len << '\n';
	
	for (unsigned i = 0; i < svar.len; i++) {
		std::ostringstream os;
		os << svar.name << std::setw (4) << std::setfill ('0') << i;
		std::string name (os.str () );// = svar.name + idx; 
   	s2e()->getDebugStream () << " >> markSymb: label: " << name << '\n';
		klee::ref<klee::Expr> label = createSymbolicValue (state, name); 
		cfg.symb_vars[symb_var_idx].labels[i] = label;
   	/*DECLARE_PLUGINSTATE (CodeXtState, state);
		Taint_Trace tt_init;
		tt_init.label = label;
		data_instance tt_init_event;
		tt_init_event.snapshot_idx = 0;
		tt_init_event.seq_num = plgState->seq_num;
		tt_init_event.is_register = 0;
		tt_init_event.addr = svar.addr + i;
		tt_init_event.len = 1;
		tt_init_event.next_pc = 0;
		tt_init_event.other_pc = 0;
		tt_init_event.is_write = 1;
		tt_init_event.in_range = 1;
		tt_init_event.valid = 1;
		tt_init_event.ti_seq_num = plgState->ti_seq_num;
		tt_init_event.tb_seq_num = plgState->tb_seq_num;
		tt_init.events.push_back (tt_init_event);
		plgState->taint_traces.push_back (tt_init);*/
		klee::ref<klee::Expr> tainted_byte = markSymbTagged (state, cfg.base_addr + svar.addr + i, label);
		if (cfg.elf_mode) {
			/*qemu: /mnt/RJFDasos/s2e/build/../s2e/klee/include/klee/Expr.h:370: static klee::ref<klee::ConstantExpr> klee::ConstantExpr::create(uint64_t, unsigned int): Assertion `v == bits64::truncateToNBits(v, w) && "invalid constant"' failed.
			klee::ref<klee::Expr> constraint_min = klee::UltExpr::create (klee::ConstantExpr::create (1, klee::Expr::Int8), tainted_byte);
			klee::ref<klee::Expr> constraint_max = klee::SgtExpr::create (klee::ConstantExpr::create (-1, klee::Expr::Int8), tainted_byte);*/
			klee::ref<klee::Expr> constraint_max = klee::UltExpr::create (klee::ConstantExpr::create ((uint8_t) 0x01, klee::Expr::Int8), tainted_byte);
			klee::ref<klee::Expr> constraint_min = klee::SgtExpr::create (klee::ConstantExpr::create ((uint8_t) 0xff, klee::Expr::Int8), tainted_byte);
			state->addConstraint (constraint_min);
			state->addConstraint (constraint_max);
		}
	   s2e()->getDebugStream () << " >> markSymb: inserting at [" << i << "]: " << tainted_byte << '\n';
		cfg.symb_vars[symb_var_idx].exprs[i] = tainted_byte;
	}
	return;
} // end fn markSymb


klee::ref<klee::Expr> CodeXt::markSymbTagged (S2EExecutionState* state, uint32_t address, klee::ref<klee::Expr> label) {
   s2e()->getMessagesStream (state)
   << "Inserting symbolic byte at " << hex (4, address)
   << " with label '" << label << "'" << '\n';
	// this allows tainting of previously tainted addresses
	// the old function read the byte as concrete
	taintAddr (state, address, 1, label, false);
	return read8 (state, address, false);
} // end markSymbTagged

/*klee::ref<klee::Expr> CodeXt::markSymbTagged_old (S2EExecutionState* state, uint32_t address, klee::ref<klee::Expr> label) {	
   // methods that did not work:
   //    klee::ref<klee::Expr> symb = klee::fromMemory (address, klee::Expr::Int8);
   // no need for state->addConstraint(symb); plus as a ConstantExpr it'll fail a constraint at a write
   klee::ref<klee::Expr> byte_const = klee::ConstantExpr::create ((uint8_t) buf, klee::Expr::Int8); //taken from writeMemory (address, val, ...);
	
   // fact, if symb_taint is concretized, it is set to zero; 0 = concretiztion (symb_taint)
   // fact, symb is essentially concrete already; symb = concretization (symb)
   // theory, symb = symb + 0 = concretization (symb) concretization (symb_tain) = concretization (symb + symb_taint)
   //klee::ref<klee::Expr> tainted_byte = klee::AddExpr::create (byte_const, label);
	klee::ref<klee::Expr> tainted_byte = labelExpr (byte_const, label);

	// now put constraints in the system to make solving easier.
	*//*klee::ref<klee::Expr> constraint_min = klee::UleExpr::create (byte_const, tainted_byte);
	klee::ref<klee::Expr> constraint_max = klee::UgeExpr::create (byte_const, tainted_byte);
	state->addConstraint (constraint_min);
	state->addConstraint (constraint_max);*/
/*
	// following doesn't work, it adds a constraint to the state assigning a constant expr (tf value) as equal to our convoluted expr for tainting
	//s2e()->getExecutor()->toConstant (*state, symb, "markSymbTagged"); 
   
   // decided not to do the following: try an extract to use the 8 LSB on a constant value
   // Creates an ExtractExpr with the given bit offset and width     static ref<Expr> create(ref<Expr> e, unsigned bitOff, Width w);
   // klee::ref<klee::Expr> symb = klee::ExtractExpr::create (klee::Expr::Int8 *//*w8 0 symb_const*//*);
} // end fn markSymbTagged*/


// anytime we create a new symb expr, we need to add it to a table for future reference
// eg, so that should we make a prop_var we can reuse it next time var needs to be prop'ed
klee::ref<klee::Expr> CodeXt::createSymbolicValue (S2EExecutionState* state, std::string label_str) {
	klee::ref<klee::Expr> label = state->createSymbolicValue (klee::Expr::Int8, label_str); 
	DECLARE_PLUGINSTATE (CodeXtState, state);
	struct label_str_to_expr l_entry;
	l_entry.label = label_str;
	l_entry.expr = label;
	plgState->labels.push_back (l_entry);
	return label;
} // end fn createSymbolicValue


// look up in that table which we create
bool CodeXt::getExpr (S2EExecutionState* state, klee::ref<klee::Expr>& e, std::string l) {
	DECLARE_PLUGINSTATE (CodeXtState, state);
	for (unsigned i = 0; i < plgState->labels.size (); i++) {
		if (l == plgState->labels[i].label) {
			e = plgState->labels[i].expr;
			return true;
		}
	}
	return false;
} // end fn getExpr


// look up in that table which we create
bool CodeXt::getLabel (S2EExecutionState* state, std::string& l, klee::ref<klee::Expr> e) {
	DECLARE_PLUGINSTATE (CodeXtState, state);
	for (unsigned i = 0; i < plgState->labels.size (); i++) {
		if (e == plgState->labels[i].expr) {
			l = plgState->labels[i].label;
			return true;
		}
	}
	return false;
} // end fn getExpr


// this function is called anytime the system needs to concretize code, per byte that is concretized.
// klee::ref<klee::ConstantExpr> concrete_val is really an 8b zero extended constant, use uint8_t
void CodeXt::onSilentConcretize (S2EExecutionState* state, uint64_t concretized_byte_addr, klee::ref<klee::Expr> concretized_expr, uint8_t concrete_val, const char* reason) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   if (!plgState->has_entered_range) {
		return;
	}

	if (isa<klee::ConstantExpr> (read8 (state, concretized_byte_addr, false) ) ) {
		s2e()->getDebugStream () << " >> oSC addr: " << hex (4, concretized_byte_addr) << " expr: " << concretized_expr << " concretized to: " << hex (1, concrete_val) << " reason: " << reason  << '\n';
		plgState->concretize_trace.push_back (concretized_byte_addr);
		klee::ref<klee::Expr> e = simplifyLabeledExpr (state, concretized_expr); //, true);
		s2e()->getDebugStream () << " >> oSC restoring to: " << e << '\n';
		write8 (state, concretized_byte_addr, e, false);
	}
	else {
		s2e()->getDebugStream () << " >> oSC addr: " << hex (4, concretized_byte_addr) << " retaint already handled" << '\n';
	}
	
	// oSC events involve an internal klee solver that adds a constraint (Eq w8 (w8 0) (LABEL)) to the state
	// this means that the label becomes worthless and will not be propagated
	// to fix this you must manually prop any taint into
	// any register that this insn writes to
	// or any memory address that this insn writes to
	// additionally, you must remove the constraint to prevent complex insns (eg add [ebx+0x14], eax; st eax contains labels that have constraints added) from scrubbing your labels
	remOnSCConstraints (state);
	return;
} // end fn onSilentConcretize


void CodeXt::remOnSCConstraints (S2EExecutionState* state) {
	// Constraints are stored in klee::ExecutionState::constraints. It's just a vector of expressions. You can iterate through it.
	// state->constraints is a klee::ConstraintManager
	// the constraints that we want to remove look like: (Eq (w8 0) (Read w8 0 v1_code_Key0000_1))
	// be careful though, fuzzFork adds these: (Eq (w32 0) (ReadLSB w32 0 v0_fuzz_symb_0))
	std::vector< klee::ref<klee::Expr> > cm_new_vector;
	klee::ConstraintManager::constraint_iterator it = state->constraints.begin ();
	klee::ConstraintManager::constraint_iterator ie = state->constraints.end ();
	for (unsigned i = 0; it != ie; ++it) {
		klee::ref<klee::Expr> it_i = *it;
		if (!(/* constraints are Expr::Eq or Expr::Not */              ((klee::Expr*) it_i.get())->getKind () == klee::Expr::Eq 
		      && /* bounds check */                                    ((klee::Expr*) it_i.get())->getNumKids () == 2 
		      && /* the optimization is to make it eq to a constant */ ((klee::Expr*) (((klee::Expr*) it_i.get())->getKid (0)).get())->getKind () == klee::Expr::Constant 
		      && /* if it's a label eq to a constant */             isLabeledExprLeaf (((klee::Expr*) it_i.get())->getKid (1) ) ) ) { // && label.find (fuzz) == std::str::npos
			//s2e()->getDebugStream () << " >> constraints[" << i << "]: " << it_i << '\n';
			cm_new_vector.push_back (it_i);
		}
		else {
			s2e()->getDebugStream () << " >> removing constraints[" << i << "]: " << it_i << '\n';
		}
		i++;
	}
	// this is a custom accessor I added
	// there was no public interface in the class to remove constraints
	// it may be worth adding a cut fn, where you can fun .erase (pos, cnt)
	state->constraints.clear ();
	for (unsigned i = 0; i < cm_new_vector.size (); i++) {
		s2e()->getDebugStream () << " >> restoring constraint[" << i << "]: " << cm_new_vector[i] << '\n';
		state->constraints.addConstraint (cm_new_vector[i]);
	}
	/* // show modified constraints
	it = state->constraints.begin ();
	ie = state->constraints.end ();
	for (unsigned i = 0; it != ie; ++it) {
		klee::ref<klee::Expr> it_i = *it;
		s2e()->getDebugStream () << " >> constraints_new[" << i << "]: " << it_i << '\n';
		i++;
	}*/
	return;
} // end fn remOnSCConstraints


void CodeXt::taintAddr (S2EExecutionState* state, uint64_t dest, uint8_t len, klee::ref<klee::Expr> label, bool is_reg) {
	std::string label_str_base = getBaseLabelStr (getLabelStr (label) );
	for (unsigned i = 0; i < len; i++) {
		klee::ref<klee::Expr> e = read8 (state, dest + i, is_reg);
		klee::ref<klee::Expr> e_i = simplifyLabeledExpr (state, e);
		// if label exists in any (prop_)* form, then don't taint it again
		if (!doesExprContainLabel (e_i, label_str_base) ) {
   		s2e()->getDebugStream () << " >> >> taintAddr tainting with label: " << label_str_base << '\n';
	   	//s2e()->getDebugStream () << " >> >> taintAddr         e: " << e << '\n';
	   	s2e()->getDebugStream () << " >> >> taintAddr from: " << e_i << '\n';
			klee::ref<klee::Expr> labeled_e = labelExpr (e_i, label);
	   	s2e()->getDebugStream () << " >> >> taintAddr   to: " << labeled_e << '\n';
			write8 (state, dest + i, labeled_e, is_reg);
		}
		else {
   		s2e()->getDebugStream () << " >> >> taintAddr already contains label: " << label_str_base << '\n';
			if (e_i != e) {
   			s2e()->getDebugStream () << " >> >> taintAddr tidied up expr: " << e_i << '\n';
				write8 (state, dest + i, e_i, is_reg);
			}
		}
	}
	return;
} // end fn taintAddr


klee::ref<klee::Expr> CodeXt::labelExpr (klee::ref<klee::Expr> e, klee::ref<klee::Expr> label) {
	//s2e()->getDebugStream () << " >> >> labelExpr      from: " << e << '\n';
	if (!doesExprContainLabel (e, label) ) {
		klee::ref<klee::Expr> labeled_e = klee::AddExpr::create (e, label);
		return labeled_e;
	}
	return e;
	//s2e()->getDebugStream () << " >> >> labelExpr        to: " << labeled_e << '\n';
} // end fn labelExpr


void CodeXt::onStateFork (S2EExecutionState* state, const std::vector<s2e::S2EExecutionState*>& newStates, const std::vector<klee::ref<klee::Expr> >& newConditions) {
	// if this is an eq/neq fork
	if (newStates.size () != 2) {
		s2e()->getDebugStream () << "oSF: newState.size: " << newStates.size () << ", skipping" << '\n';
		return;
	}
	//remFalseConstraints (newStates[0]);
	newStates[0]->constraints.clear ();
	newStates[1]->constraints.clear ();
	klee::ref<klee::Expr> final_constraint;
	struct ConstraintExpr c_e = getConstraint (newConditions[0]);
	klee::ref<klee::Expr> solved_expr = scrubLabels (newStates[0], c_e.symb);

	if ((c_e.eq && c_e.conc == solved_expr) || (!c_e.eq && c_e.conc == solved_expr) ) {
		s2e()->getDebugStream () << "oSF: newState[0] has correct constraint" << '\n';
		newStates[0]->constraints.addConstraint (newConditions[0]);
		final_constraint = newConditions[0];
		s2e()->getDebugStream () << "oSF: constraint enforced: " << c_e.conc << (c_e.eq ? "==" : "!=") << solved_expr << ": " << final_constraint << '\n';
   	terminateStateEarly_wrap (newStates[1], std::string ("onStateFork intercepted invalid condition"), false);
	}
	else {
		//s2e()->getDebugStream () << "oSF: newState[1] has correct constraint, moved to netState[0]" << '\n';
		s2e()->getDebugStream () << "oSF: newState[1] has correct constraint" << '\n';
		newStates[1]->constraints.addConstraint (newConditions[1]);
		final_constraint = newConditions[1];
		c_e.eq = !c_e.eq;
		s2e()->getDebugStream () << "oSF: constraint enforced: " << c_e.conc << (c_e.eq ? "==" : "!=") << solved_expr << ": " << final_constraint << '\n';
		s2e()->getDebugStream () << "oSF: switch states" << '\n';
	   //s2e()->getExecutor()->doStateSwitch (newStates[0], newStates[1]);
	   //s2e()->getExecutor()->selectNextState (newStates[0]);
   	terminateStateEarly_wrap (newStates[0], std::string ("onStateFork intercepted invalid condition"), false);
	}
	//s2e()->getDebugStream () << "oSF: constraint enforced: " << c_e.conc << (c_e.eq ? "==" : "!=") << solved_expr << ": " << final_constraint << '\n';
   //terminateStateEarly_wrap (newStates[1], std::string ("onStateFork intercepted invalid condition"), false);
	return;
} // end fn onStateFork


struct ConstraintExpr CodeXt::getConstraint (klee::ref<klee::Expr> c) {
	struct ConstraintExpr c_e;
	c_e.eq = false;
	c_e.conc = 0;
	c_e.symb = 0;
	klee::ref<klee::Expr> e = c;
	if (e.isNull () ) {
		s2e()->getDebugStream () << " >> isConstraint ERROR with expr" << '\n';
		return c_e;
	}
	if (isa<klee::ConstantExpr> (e) ) {
		// ConstantExpr have no labels, nor no subexpr by definition. nothing to do here.
		return c_e;
	}
	// Proper conditions are in the format: (Eq(l)(r)); or, (Not(Eq(l)(r))). Such that l or r is a ConstantExpr, but not both 
	// see if we need to peel off a Not
	c_e.eq = true;
	if (((klee::Expr*) e.get())->getKind () == klee::Expr::Not) {
		unsigned e_kids = ((klee::NotExpr*) e.get())->getNumKids ();
		if (e_kids != 1) {
			s2e()->getDebugStream () << " >> isConstraint malformed Not: " << e_kids << '\n';
			return c_e;
		}
		e = ((klee::Expr*) e.get())->getKid (0);
		c_e.eq = false;
	}
	// if this isn't an Eq; or we peeled off a Not and this isn't an Eq
	if (((klee::Expr*) e.get())->getKind () != klee::Expr::Eq) {
		s2e()->getDebugStream () << " >> isConstraint cond wasn't an Eq: " << ((klee::Expr*) e.get())->getKind () << '\n';
		return c_e;
	}
	// Eq is binary operator
	unsigned e_kids = ((klee::EqExpr*) e.get())->getNumKids ();
	if (e_kids != 2) {
		// don't worry about this condition now, focus on the binary tree
		s2e()->getDebugStream () << " >> isConstraint malformed Eq: " << e_kids << '\n';
		return c_e;
	}

	klee::ref<klee::Expr> e_0 = ((klee::Expr*) e.get())->getKid (0);
	klee::ref<klee::Expr> e_1 = ((klee::Expr*) e.get())->getKid (1);
	// one must be const, the other symb, find which is which
	if (isa<klee::ConstantExpr> (e_0) && isa<klee::ConstantExpr> (e_1) ) {
		s2e()->getDebugStream () << " >> isConstraint malformed cond, two constants" << '\n';
		return c_e;
	}
	if (!isa<klee::ConstantExpr> (e_0) && !isa<klee::ConstantExpr> (e_1) ) {
		s2e()->getDebugStream () << " >> isConstraint malformed cond, two symbolics" << '\n';
		return c_e;
	}
	if (isa<klee::ConstantExpr> (e_0) ) {
		c_e.conc = e_0;
		c_e.symb = e_1;
	}
	else {
		c_e.conc = e_1;
		c_e.symb = e_0;
	}
	return c_e;
} // end fn getConstraint


void CodeXt::simplifyMemory (S2EExecutionState* state) {
   for (unsigned i = 0; i < cfg.byte_len; i++) {
		simplifyAddr (state, cfg.base_addr + i, false);
	}
	return;
} // end fn simplifyMemory


void CodeXt::simplifyAddr (S2EExecutionState* state, uint64_t pc, bool is_reg) {
	klee::ref<klee::Expr> e = read8 (state, pc, is_reg);
	klee::ref<klee::Expr> eo = simplifyLabeledExpr (state, e);
	if (eo != e) {
		s2e()->getDebugStream () << " >> simplifyAddr'd: " << hex (4, pc) << '\n';
		write8 (state, pc, eo, is_reg);
	}
	return;
} // end fn simplifyMemory


klee::ref<klee::Expr> CodeXt::simplifyLabeledExpr (S2EExecutionState* state, klee::ref<klee::Expr> e, bool do_prop) {
	//s2e()->getDebugStream () << " >> simplifyLabeledExpr kind: " << ((klee::Expr*) e.get())->getKind () << " bits: " << ((klee::Expr*) e.get())->getWidth () << '\n';
	if (isa<klee::ConstantExpr> (e) ) {
		return e;
	}
	if (!do_prop && isLabeledExprLeaf (e) ) {
		s2e()->getDebugStream () << " >> simplifyLabeledExpr leaf: " << e << '\n';
		return e;
	}
	s2e()->getDebugStream () << " >> simplifyLabeledExpr e in: " << e << '\n';
	std::vector<klee::ref<klee::Expr> > labels;
	// consider adding a case to skip scrub/labeling if the set of labels returned by handleOp == set of labels in e without handleOp
	if (handleOp (0, e, labels) ) {
		//s2e()->getDebugStream () << " >> simplifyLabeledExpr opHandler true" << '\n';
		e = scrubLabels (state, e);
		for (unsigned i = 0; i < labels.size (); i++) {
			//s2e()->getDebugStream () << " >> simplifyLabeledExpr adding found label: " << labels[i] << '\n';
			if (do_prop) {
				e = labelExpr (e, getPropLabel (state, labels[i]) );	
			}
			else {
				e = labelExpr (e, labels[i]);
			}
		}
		s2e()->getDebugStream () << " >> simplifyLabeledExpr'd: " << e << '\n';
		return e;
	}
	s2e()->getDebugStream () << " >> ERROR simplifyLabeledExpr opHandler false" << '\n';
	return e;
} // end simplifyLabeledExpr

/*
// DEPRECATED: Use simplifyLabeledExpr instead
// this solves the equation (scrubs the labels and returns a concrete value) and then relabels that concrete value
// note that it cheats a little, lazy extraction, as all labels in the expression are retained
// for example if we have an extract w8 xor w32 concat w32 <- then all concat's byte's labels are retained instead of jsut the proper offset's 
klee::ref<klee::Expr> CodeXt::tidyLabels (S2EExecutionState* state, klee::ref<klee::Expr> e) {
	if (isa<klee::ConstantExpr> (e) ) {
		return e;
	}
	if (!allOps8 (e) ) {
		return e;
	}
	std::vector< klee::ref<klee::Expr> > labels = getLabels (e);
	// scrubLabels also solves complex formulas, so might as well run it even if there aren't any labels in the expr
	klee::ref<klee::Expr> e_tidied = scrubLabels (state, e);
	for (unsigned i = 0; i < labels.size (); i++) {
		e_tidied = labelExpr (e_tidied, labels[i]);
	}
	return e_tidied;
} // end fn tidyLabels
*/

// does there exist any sub expr with a width != 8
bool CodeXt::allOps8 (klee::ref<klee::Expr> e) {
	if (((klee::Expr*) e.get())->getWidth () != 8) {
		return false;
	}
	for (unsigned i = 0; i < ((klee::Expr*) e.get())->getNumKids (); i++) {
		klee::ref<klee::Expr> ei = ((klee::Expr*) e.get())->getKid (i);
		if (((klee::Expr*) ei.get())->getWidth () != 8) {
			return false;
		}
		else if (((klee::Expr*) ei.get())->getNumKids () > 0) {
			if (!allOps8 (ei) ) {
				return false;
			}
		}
	}
	return true;
} // end fn allOps8


bool CodeXt::isNoExtracts (klee::ref<klee::Expr> e) {
	if (((klee::Expr*) e.get())->getKind () == klee::Expr::Extract) {
		return false;
	}
	for (unsigned i = 0; i < ((klee::Expr*) e.get())->getNumKids (); i++) {
		klee::ref<klee::Expr> ei = ((klee::Expr*) e.get())->getKid (i);
		if (((klee::Expr*) e.get())->getKind () == klee::Expr::Extract) {
			return false;
		}
		else if (((klee::Expr*) ei.get())->getNumKids () > 0) {
			if (!isNoExtracts (ei) ) {
				return false;
			}
		}
	}
	return true;
} // end fn isNoExtracts


bool CodeXt::isOpBitwise (klee::Expr::Kind k) {
	if (k == klee::Expr::Xor || k == klee::Expr::Or || k == klee::Expr::And || k == klee::Expr::Not) {
		return true;
	}
	return false;
} // end fn isOpBitwise


// what constitutes a labeled expr:
// it is an (Add (Constant|Expr) (Read))
// or       (Add (Constant|Expr) (isLabeledExprLeaf?)) 
// ie       (Add (Constant|Expr) (Add (Read) (Read)))
// etc eg   (Add (Constant|Expr) (Add (Read) (Add (Read) (Read))))
bool CodeXt::isLabeledExprLeaf (klee::ref<klee::Expr> e) {
	if (isa<klee::ConstantExpr> (e) ) {
		return false;
	}
	
	// the simplest form is just a Read
	if (((klee::Expr*) e.get())->getKind () == klee::Expr::Read && ((klee::Expr*) e.get())->getNumKids () == 1) {
		return true;
	}
	
	// otherwise its a combination of Reads and other Expr using Adds
	if (((klee::Expr*) e.get())->getKind () != klee::Expr::Add) {
		return false;
	}
	// Adds always have 2 kids
	unsigned e_kids = ((klee::Expr*) e.get())->getNumKids ();
	if (e_kids != 2) {
		return false;
	}
	//s2e()->getDebugStream () << " >> isLabeledExprLeaf potential leaf: " << e << '\n';
	//s2e()->getDebugStream () << " >> isLabeledExprLeaf potential leaf call" << '\n';
	klee::ref<klee::Expr> e_0 = ((klee::Expr*) e.get())->getKid (0);
	klee::ref<klee::Expr> e_1 = ((klee::Expr*) e.get())->getKid (1);
	if (isa<klee::ConstantExpr> (e_0) && (((klee::Expr*) e_1.get())->getKind () == klee::Expr::Read || isLabeledExprLeaf (e_1) ) ) {
		return true;
	} 
	if (isa<klee::ConstantExpr> (e_1) && (((klee::Expr*) e_0.get())->getKind () == klee::Expr::Read || isLabeledExprLeaf (e_0) ) ) {
		return true;
	}
	if (((klee::Expr*) e_0.get())->getKind () == klee::Expr::Read && ((klee::Expr*) e_1.get())->getKind () == klee::Expr::Read) {
		return true;
	} 
	if (isLabeledExprLeaf (e_0) && ((klee::Expr*) e_1.get())->getKind () == klee::Expr::Read) {
		return true;
	} 
	if (((klee::Expr*) e_0.get())->getKind () == klee::Expr::Read && isLabeledExprLeaf (e_1) ) {
		return true;
	} 
	return false;
} // end fn isLabeledExprLeaf


bool CodeXt::handleOp (unsigned offset, klee::ref<klee::Expr> e, std::vector<klee::ref<klee::Expr> >& labels, bool is_bitwise) {
	if (e.isNull () ) {
		s2e()->getDebugStream () << " >> handleOp ERROR with expr" << '\n';
		return false;
	}
	//s2e()->getDebugStream () << " >> handleOp labels " << labels.size () << " is_b? " << is_bitwise << " e: " << e << '\n';
	if (isa<klee::ConstantExpr> (e) ) {
		// ConstantExpr have no labels, nor no subexpr by definition. nothing to do here.
		return true;
	}
	
	// already returns unique labels, and most simplest form of them
	std::vector<klee::ref<klee::Expr> > li = getLabels (e); 
	// if there is only 1 label in the entire expr, then just return it. no need to traverse children
	// if every child only has w8, then we can just solve it and tack on any labels
	if (allOps8 (e) || (li.size () == 1 && isNoExtracts (e) && ((klee::Expr*) e.get())->getKind () != klee::Expr::Concat) ) {
		//s2e()->getDebugStream () << " >> handleOp:isOnlyChild||isAllOps8: " << e << '\n';
		labelVectorAdd (labels, li);
		return true;
	}
	//s2e()->getDebugStream () << " >> handleOp labels in e: " << li.size () << '\n';
	
	if (((klee::Expr*) e.get())->getWidth () == 8 && (!is_bitwise || offset == 0) && isLabeledExprLeaf (e) ) {
		//s2e()->getDebugStream () << " >> handleOp:isLabeledExprLeaf: " << e << '\n';
		// if we are at the correct offset then snag the labels
		// for now e.width must be 8
		labelVectorAdd (labels, li);
		return true;
	}
	else if (isOpBitwise (((klee::Expr*) e.get())->getKind () ) ) {
		// bitwise ops (eg xor, or, and, not) of w8 means that we only need to extract labels from the correct offset
		// since any byte only impacts that byte's offset in the solved value 
		return opBitwise (offset, e, labels);
	}
	else if (((klee::Expr*) e.get())->getKind () == klee::Expr::Concat) {
		// concats will recursively call here, adjusting offset as necessary, which means all labels get ignored except when offset == 0
		return opConcat (offset, e, labels, is_bitwise);
	}
	else if (((klee::Expr*) e.get())->getKind () == klee::Expr::Extract) {
		if (((klee::Expr*) e.get())->getWidth () != 8) {
			return false;
		}
		// extracts have an offset, we don't give it one
		return opExtract8 (e, labels);
	}
	else if (!(isOpBitwise (((klee::Expr*) e.get())->getKind () ) ) ) {
		// non bitwise ops (eg add, sub) means that we need to extract all labels
		// since any byte could potentiall impact all over byte offsets in the solved value (eg 0xffffffff + 0x01 = 0x00000000)
		return opNonBitwise (offset, e, labels);
	}
	// unhandled case
	s2e()->getDebugStream () << " >> ERROR handleOp unhandled case: " << e << '\n';
	return false;
} // end fn handleOp


// there are several cases that we may want to simplify/reduce the labels within an expr
// in particular with 1to1 insns (xor, or, and, not)
// for instance
// (Extract w8 0 (Xor w32 (w32 3085654150) (Concat w32 (Add w8 (w8 92) (Read w8 0 v5_prop_code_Key0003_5)) (Concat w24 (Add w8 (w8 30) (Read w8 0 v6_prop_code_Key0002_6)) (Concat w16 (Add w8 (w8 186) (Read w8 0 v7_prop_code_Key0001_7)) (Add w8 (w8 146) (Read w8 0 v8_prop_code_Key0000_8)))))))
// would be equivalent and simpler as (Add w8 (w8 [solved value of byte]) (Read w8 0 v8_prop_code_Key0000_8)
// should return an expression for the extracted byte with appropriate labels
bool CodeXt::opExtract8 (klee::ref<klee::Expr> e, std::vector<klee::ref<klee::Expr> >& labels) {
	// error checks
	if (isa<klee::ConstantExpr> (e) ) {
		return false;
	}
	// no need to extract anything if is w8 all around, probably a vestigal condition.
	/*if (allOps8 (e) ) {
		return false;
	}*/
	// this only handles Extract w8 expressions
	if (((klee::Expr*) e.get())->getKind () != klee::Expr::Extract || ((klee::Expr*) e.get())->getWidth () != 8) {
		s2e()->getDebugStream () << " >> opExtract8 wrong operator: " << ((klee::Expr*) e.get())->getKind () << " or wrong bits: " << ((klee::Expr*) e.get())->getWidth () << '\n';
		return false;
	}
	
	unsigned offset = ((klee::ExtractExpr*) e.get())->offset;
	//s2e()->getDebugStream () << " >> opExtract8 offset: " << offset << '\n';
	// extracts only have 1 kid
	if (((klee::Expr*) e.get())->getNumKids () != 1) {
		s2e()->getDebugStream () << " >> opExtract8 wrong (!=1) number of kids: " << ((klee::Expr*) e.get())->getNumKids () << '\n';
	}
	//klee::ref<klee::Expr> kid = ((klee::Expr*) e.get())->getKid (0);
	//s2e()->getDebugStream () << " >> opExtract8 kid kind: " << ((klee::Expr*) kid.get())->getKind () << " bits: " << ((klee::Expr*) kid.get())->getWidth () << '\n';
	//return handleOp (offset, kid, labels);
	return handleOp (offset, ((klee::Expr*) e.get())->getKid (0), labels);
} // end fn opExtract8


// given solved_e, get labels from parent (infer via e) at bit offset
bool CodeXt::opBitwise (unsigned offset, klee::ref<klee::Expr> e, std::vector<klee::ref<klee::Expr> >& labels) {
	if (!isOpBitwise (((klee::Expr*) e.get())->getKind () ) ) {
		s2e()->getDebugStream () << " >> opBitwise wrong operator: " << ((klee::Expr*) e.get())->getKind () << '\n';
		return false;
	}
	//unsigned e_width = ((klee::Expr*) e.get())->getWidth ();
	unsigned e_kids = ((klee::Expr*) e.get())->getNumKids ();
	//s2e()->getDebugStream () << " >> opBitwise " << " " << kid << '\n';
	//s2e()->getDebugStream () << " >> opBitwise operator: " << ((klee::Expr*) e.get())->getKind ()  << " bits: " << e_width << '\n';
	// we can easily simplify binary bitwise operations (bit ops with two operands, particularly if one operand isaConstantExpr)
	if (e_kids != 2) {
		s2e()->getDebugStream () << " >> opBitwise wrong (!=2) number of kids: " << e_kids << '\n';
		return false;
	}
	for (unsigned i = 0; i < e_kids; i++) {
		klee::ref<klee::Expr> ei = ((klee::Expr*) e.get())->getKid (i);
		if (!handleOp (offset, ei, labels) ) {
			return false;
		}
	}
	return true;
} // end fn opBitwise


bool CodeXt::opNonBitwise (unsigned offset, klee::ref<klee::Expr> e, std::vector<klee::ref<klee::Expr> >& labels) {
	if (isOpBitwise (((klee::Expr*) e.get())->getKind () ) && (((klee::Expr*) e.get())->getKind () != klee::Expr::Add /* || other ops */) ) {
		s2e()->getDebugStream () << " >> opNonBitwise wrong operator: " << ((klee::Expr*) e.get())->getKind () << '\n';
		return false;
	}
	//unsigned e_width = ((klee::Expr*) e.get())->getWidth ();
	unsigned e_kids = ((klee::Expr*) e.get())->getNumKids ();
	//s2e()->getDebugStream () << " >> opNonBitwise operator: " << ((klee::Expr*) e.get())->getKind ()  << " bits: " << e_width << '\n';
	// for now only focus on binary operands
	if (e_kids != 2) {
		s2e()->getDebugStream () << " >> opNonBitwise wrong (!=2) number of kids: " << e_kids << '\n';
		return false;
	}
	for (unsigned i = 0; i < e_kids; i++) {
		klee::ref<klee::Expr> ei = ((klee::Expr*) e.get())->getKid (i);
		if (!handleOp (offset, ei, labels, false) ) {
			return false;
		}
	}
	return true;
} // end fn opNonBitwise


// input offset is almost reversed within the concat expr
// 0 is the LSB, bits 0 to 7, which are the furthest nested in w8 expr
bool CodeXt::opConcat (unsigned offset, klee::ref<klee::Expr> e, std::vector<klee::ref<klee::Expr> >& labels, bool is_bitwise) {
	if (((klee::Expr*) e.get())->getKind () != klee::Expr::Concat) {
		s2e()->getDebugStream () << " >> opConcat wrong operator: " << ((klee::Expr*) e.get())->getKind () << '\n';
		return false;
	}
	unsigned e_width = ((klee::Expr*) e.get())->getWidth ();
	unsigned e_kids = ((klee::ConcatExpr*) e.get())->getNumKids ();
	unsigned bytes_wide = e_width / 8;
	//s2e()->getDebugStream () << " >> opConcat is_bitwise? " << is_bitwise <<  " bits: " << e_width << " bytes: " << bytes_wide << '\n';
	
	
	// if this is not bitwise, then it's a subexpr of, for instance, an add
	// so we want to save all the labels of each subexpr here. (be accumulative)
	// note that if deeper children involve an extract/bitwise op, then those recursion levels would not be accumulative 
	if (!is_bitwise) {
		for (unsigned i = 0; i < e_kids; i++) {
			handleOp (offset, ((klee::Expr*) e.get())->getKid (i), labels, false);
		}
	}
	
	// this is a special case, where 
	// concats can have many children eg four Bytes put together to make a 32b; but it can be any length, like 8
	// note that this also catches the last branch of a binary treed concat
	unsigned dir_acc_kid = (bytes_wide - 1) - (offset / 8);
	if (e_kids == bytes_wide && dir_acc_kid < e_kids) {
		//s2e()->getDebugStream () << " >> opConcat direct address deCat: " << e_kids << '\n';
		// then we do not have a nested Concat
		// we can address the byte directly
		klee::ref<klee::Expr> ei = ((klee::Expr*) e.get())->getKid (dir_acc_kid);
		// 24(MSB, bits 24 to 31)->0, 16(bits 16 to 23)->1, 8(bits 8 to 15)->2, 0(LSB, bits 0 to 7)->3
		return handleOp (0, ei, labels);
	}
	
	// the only format I've seen in S2E is 2 children (one leaf and one concat branch) (binary tree)
	// the lower offset is the deeper child
	if (e_kids != 2) {
		// don't worry about this condition now, focus on the binary tree
		s2e()->getDebugStream () << " >> opConcat malformed concat: " << e_kids << '\n';
		return false;
	}

	klee::ref<klee::Expr> e_0 = ((klee::Expr*) e.get())->getKid (0);
	klee::ref<klee::Expr> e_1 = ((klee::Expr*) e.get())->getKid (1);
	// in the binary tree concat there are 3 cases: kid0 concat/kid1 notconcat, kid1 concat/kid0 notconcat, niether are concat	
	// well, there is a fourth: both are concat, but I haven't seen it, so let's skip it for now
	if (((klee::Expr*) e_0.get())->getKind () == klee::Expr::Concat && ((klee::Expr*) e_1.get())->getKind () == klee::Expr::Concat) {
		// let's not worry about the both concat case
		s2e()->getDebugStream () << " >> opConcat malformed 1 concat: " << e_kids << '\n';
		return false;
	}



	if (((klee::Expr*) e_0.get())->getKind () != klee::Expr::Concat && ((klee::Expr*) e_1.get())->getKind () == klee::Expr::Concat) {
		// e_0 is the MoreSB
		if ((e_width - ((klee::Expr*) e_0.get())->getWidth () ) == offset) {// eg 32 - 8 == 24, then we want this
			//s2e()->getDebugStream () << " >> opConcat 1 found the offset: " << offset << '\n';
			return handleOp (0, e_0, labels);
		}
		//s2e()->getDebugStream () << " >> opConcat 2 skipping to next offset: " << offset << '\n';
		return handleOp (offset, e_1, labels);
	}
	// I haven't seen this, so I have a error catcher here, but the code inside should mimic the previous condition
	if (((klee::Expr*) e_0.get())->getKind () == klee::Expr::Concat && ((klee::Expr*) e_1.get())->getKind () != klee::Expr::Concat) {
		/*// e_0 is the MoreSB
		if ((e_width - ((klee::Expr*) e_1.get())->getWidth () ) == offset) {// eg 32 - 8 == 24, then we want this
			s2e()->getDebugStream () << " >> opConcat 2 found the offset: " << offset << '\n';
			return handleOp (0, e_1, labels);
		}
		return handleOp (offset, e_0, labels);*/
		// let's not worry about this case just now
		s2e()->getDebugStream () << " >> opConcat malformed 2 concat" << '\n';
		return false;
	}
	if (((klee::Expr*) e_0.get())->getKind () != klee::Expr::Concat && ((klee::Expr*) e_1.get())->getKind () != klee::Expr::Concat) {
		// e_0 is the MoreSB
		//s2e()->getDebugStream () << " >> opConcat neither kids are concat, offset: " << offset << '\n';
		if (offset == 0) {
			return handleOp (0, e_1, labels);
		}
		// we are assuming that the offsets are always 8b apart
		else if ((offset % 8) != 0) { // this also catch offset < 8
			return false;
		}
		return handleOp (offset - 8, e_0, labels);
	}
	s2e()->getDebugStream () << " >> ERROR opConcat unhandled case: " << offset << " e: " << e << '\n';
	return false;
} // end fn opConcat


// uniquely
std::vector<klee::ref<klee::Expr> > CodeXt::labelVectorAdd (std::vector<klee::ref<klee::Expr> >& ls, std::vector<klee::ref<klee::Expr> > ls_to_add) {
	for (unsigned i = 0; i < ls_to_add.size (); i++) {
		labelVectorAdd (ls, ls_to_add[i]);
	}
	return ls;
} // end fn labelVectorAdd


// uniquely
std::vector<klee::ref<klee::Expr> > CodeXt::labelVectorAdd (std::vector<klee::ref<klee::Expr> >& ls, klee::ref<klee::Expr> l) {
	// search for existing duplicates
	bool found = false;
	for (unsigned i = 0; !found && i < ls.size (); i++) {
		if (l == ls[i]) {
			found = true;
			return ls;
		}
		else if (isLabelSimplerForm (ls[i], l) ) {
			ls[i] = l;
			found = true;
			return ls;
		}
	}
	ls.push_back (l);
	return ls;
} // end fn labelVectorAdd


std::vector< klee::ref<klee::Expr> > CodeXt::getLabels (klee::ref<klee::Expr> e) {
	std::vector< klee::ref<klee::Expr> > labels;
	if (isa<klee::ConstantExpr> (e) ) {
		return labels;
	}
	//s2e()->getDebugStream () << " >> getLabels e: "<< e << '\n'; 
	for (unsigned i = 0; i < ((klee::Expr*) e.get())->getNumKids (); i++) {
		klee::ref<klee::Expr> ei = ((klee::Expr*) e.get())->getKid (i);
		//s2e()->getDebugStream () << " >> getLabels kid[" << i << "] is: "<< ei << '\n';
		if (((klee::Expr*) ei.get())->getKind () == klee::Expr::Read) {
			labelVectorAdd (labels, ei);
		}
		else if (((klee::Expr*) ei.get())->getNumKids () > 0) {
			//s2e()->getDebugStream () << " >> getLabels recursing [" << i << "]" << '\n';
			labelVectorAdd (labels, getLabels (ei) );
		}
	}
	return labels;
} // end fn getLabels


std::string CodeXt::getLabelStr (klee::ref<klee::Expr> e) {
	// a ref <Expr> is a reference to am Expr, so ref<Expr>.get () returns a pointer to the Expr object
	// (Read w8 0 v1_code_Key0000_1)
	//s2e()->getDebugStream () << " >> taintReg label.get: " << taint_label.get() << '\n'; // prints a memory address
	//s2e()->getDebugStream () << " >> taintReg label.get->getKind: " << taint_label.get()->getKind () << '\n'; // prints 'Read'
	//s2e()->getDebugStream () << " >> taintReg label.get->getNumKids: " << taint_label.get()->getNumKids () << '\n'; // prints '1'
	//s2e()->getDebugStream () << " >> taintReg label.get->kind: " << ((klee::ReadExpr*) e.get())->kind << '\n';
	//s2e()->getDebugStream () << " >> getLabelStr e: "<< e << '\n'; 
	if (((klee::Expr*) e.get())->getKind () != klee::Expr::Read) {
		s2e()->getDebugStream () << " >> getLabelStr not Expr::Read, is: "<< ((klee::Expr*) e.get())->getKind () << '\n';  // if it had been a read, it would print 'Read'
		return "UNK:ERROR";
	}
	//klee::ref<klee::Expr> ei = ((klee::Expr*) e.get())->getKid (i);
	//s2e()->getDebugStream () << " >> getLabelStr label.get->index: " << ((klee::ReadExpr*) e.get())->index << '\n'; // prints '0'
	//s2e()->getDebugStream () << " >> getLabelStr label.get->updates.root->size: " << e_ptr->updates.root->size << '\n'; // prints '1'
	//s2e()->getDebugStream () << " >> getLabelStr label.get->updates.root.constValues.size(): " << e_ptr->updates.root->constantValues.size () << '\n'; // prints 
	//for (unsigned i = 0; i < e_ptr->updates.root->constantValues.size (); i++) {
	//	s2e()->getDebugStream () << " >> getLabelStr label.get->updates.root->constantValues[" << i << "]: " << e_ptr->updates.root->constantValues[i] << '\n';
	//}
	
	// klee::ReadExpr has public attribute UpdateList updates
	std::string label = ((klee::ReadExpr*) e.get())->updates.root->name;
	//s2e()->getDebugStream () << " >> getLabelStr label.get->updates.root->name: " << label << '\n'; // prints 'v1_code_Key0000_1'
	return label;
} // end fn getLabelStr


std::string CodeXt::getBaseLabelStr (std::string s) {
	std::string os = s;
	//s2e()->getDebugStream () << " >> getBaseLabel  in: " << os << '\n';
	os = trimLabelStr (os);
	if (os[0] != 'p') {
		//s2e()->getDebugStream () << " >> getBaseLabel out: " << os << '\n';
		return os;
	}
	while (os.find ("prop_") != std::string::npos) {
		os.erase (0, 5);
	}
	//s2e()->getDebugStream () << " >> getBaseLabel out: " << os << '\n';
	return os;
} // end fn getBaseLabelStr


std::string CodeXt::trimLabelStr (std::string s) {
	std::string os = s;
	// to do this, get the label_str for the Read Expr, trim off the ^v[0-9]+_ and _[0-9]+$ 
	//label_str.erase (0, 3); // get rid of v1_
	if (os[0] != 'v') {
		// error, odd format
		return os;
	}
	unsigned i = 0;
	while (os[i] != '_') {
		i++;
	} 
	os.erase (0, i + 1);
	
	i = os.length () - 1;
	while (os[i] != '_') {
		i--;
	}
	os.erase (i, os.length () - i);	
	return os;
} // end fn trimLabelStr


bool CodeXt::isLabelSimplerForm (klee::ref<klee::Expr> haystack, klee::ref<klee::Expr> needle) {
	std::string h = getLabelStr (haystack);
	std::string n = getLabelStr (needle);
	if (getBaseLabelStr (h) == getBaseLabelStr (n) && n.length () < h.length () ) {
		return true;
	}
	return false;
} // end fn isLabelSimplerForm


klee::ref<klee::Expr> CodeXt::getPropLabel (S2EExecutionState* state, klee::ref<klee::Expr> label) {
	// taint by getting the labels and then modifying them to be a "prop" (propagated) version of the label
	std::string label_str;
	if (!getLabel (state, label_str, label) ) {
		label_str = getLabelStr (label); 
		label_str = trimLabelStr (label_str);
	}
	s2e()->getDebugStream () << " >> >> getPropLabel label: " << label << ", label.str: " << label_str << '\n';
	return getPropLabel (state, label_str);
}

klee::ref<klee::Expr> CodeXt::getPropLabel (S2EExecutionState* state, std::string label_str) {
	label_str = "prop_" + label_str;
	s2e()->getDebugStream () << " >> >> getPropLabel using label_str: " << label_str << '\n';
	// if label_str already exists within the Label_Table, then use its expr, else make a new one for it
	klee::ref<klee::Expr> e;
	if (!getExpr (state, e, label_str) ) { // from Label_Table
		s2e()->getDebugStream () << " >> >> getPropLabel creating expr for: " << label_str << '\n';
		e = createSymbolicValue (state, label_str); 
	}
	return e;
} // end fn getPropLabel


// search all the labels within a given expr for any that contain a substring that is l_str (eg label would match prop_label)
// note that if you use this check, but then simplifyLabeledExpr, then that label may be solved out. ie only run after simplify
bool CodeXt::doesExprContainLabel (klee::ref<klee::Expr> e, std::string l_str) {
	if (isa<klee::ConstantExpr> (e) ) {
		return false;
	}
	std::vector< klee::ref<klee::Expr> > l = getLabels (e);
	for (unsigned i = 0; i < l.size (); i++) {
		std::string li_str = getLabelStr (l[i]);
		if (li_str.find (l_str) != std::string::npos) {
			//s2e()->getDebugStream () << " >> >> doesExprContainLabel: " << li_str << '\n';
			return true;
		}
	}
	return false;
} // end fn doesExprContainLabel


bool CodeXt::doesExprContainLabel (klee::ref<klee::Expr> e, klee::ref<klee::Expr> l) {
	return doesExprContainLabel (e, getLabelStr (l) );
} // end fn doesExprContainLabel


void CodeXt::scrubAddr (S2EExecutionState* state, uint64_t addr, uint8_t len, bool is_reg) {					
   s2e()->getDebugStream () << " >> >> scrubAddr len: " << hex (1, len) << '\n';
	for (unsigned i = 0; i < len; i++) {
		klee::ref<klee::Expr> e = read8 (state, addr + i, is_reg);
		if (!isa<klee::ConstantExpr> (e) ) {
			klee::ref<klee::Expr> scrubbed_e = scrubLabels (state, e);
			write8 (state, addr + i, scrubbed_e, is_reg);
   		s2e()->getDebugStream () << " >> >> scrubAddr[" << i <<"]: scrubbed" << '\n';
   		//s2e()->getDebugStream () << " >> >> scrubAddr[" << i <<"]: debug mocked scrubbed" << '\n';
		}
		else {
   		s2e()->getDebugStream () << " >> >> scrubAddr[" << i <<"]: already clean" << '\n';
		}
	}
	return;
} // end fn scrubAddr


// this quite simply just solves the expr and returns a constantexpr
klee::ref<klee::Expr> CodeXt::scrubLabels (S2EExecutionState* state, klee::ref<klee::Expr> e) {
	if (e.isNull () ) {
		s2e()->getDebugStream () << "!! ERROR: scrubLabels: null expression\n";
		return klee::ref<klee::Expr> (0);
	}
	if (isa<klee::ConstantExpr> (e) ) {
		return e;
   }
	klee::ref<klee::ConstantExpr> e_solved;
	s2e()->getExecutor()->getSolver()->getValue (klee::Query (state->constraints, e), e_solved); 
	return e_solved;
} // end fn scrubLabels


void CodeXt::enforceTaints (S2EExecutionState* state, std::vector<data_instance> reg_writes, std::vector<data_instance> data_writes) {
	enforceTaintsAddr (state, reg_writes, true);
	enforceTaintsAddr (state, data_writes, false);
	return;
} // end fn enforceTaints


// divide things up into three stages: modifiying the writes to limit propagation, scrub any write destinations that can be, then do the taints
void CodeXt::enforceTaintsAddr (S2EExecutionState* state, std::vector<data_instance> writes, bool is_reg) {
	// adjust the offsets and sizes of the tainting
	// as well as scrub any destinations that should be
	for (unsigned i = 0; i < writes.size (); i++) {
		trans_instance trans;
		DECLARE_PLUGINSTATE (CodeXtState, state);
		for (int k = plgState->trans_trace.insns.size () - 1; k >= 0; k--) {
			if (plgState->trans_trace.insns[k].addr == (writes[i].other_pc - cfg.base_addr) ) {
				trans = plgState->trans_trace.insns[k];
				k = -1;
			}
		}
		s2e()->getDebugStream () << " >> >> enforceTaints_pre limiting over propagation for insn: " << trans.disasm << '\n';
		// limit over propagation
		// for instance, if the instruction has an immediate value input and is a 1 to 1 bitmap operation (eg mov, xor, or, and, not)
		// then we do not need to taint all written byte by all instruction tainted bytes.
		// we could instead taint on a 1 to 1 basis

		// A note regarding mov reg,imm insns: (and other isImmSrcInsn)
		// use position within insn to determine offset
		// len will always be 1 bc this is called for every oSC event (each byte actually made symbolic)
		// in the machine code the bytes are little endian in memory (a la Intel, what is being emulated), address them the same way in the klee register memory object
		// eg mov eax, 0xff looks like b8 ff 00 00 00 in memory, and if we iterate the klee reg object we would see ff 00 00 00
		// bn mov  al, 0xff looks like b0 ff in memory
		
		unsigned offset = 0;
		unsigned len = is_reg ? 4 : writes[i].len;
		uint64_t src_pc = writes[i].next_pc;
		
		// don't taint all 4B of the reg if the dest wasn't e?x
		if (is_reg) {
			switch (regAddressingType (state, trans.disasm) ) {
				case 4: // ?l lower of lower 2B
					// 0->0 // little-endian
					len = 1;
					break;
				case 3: // ?h higher of lower 2B
					offset = 1; // 0->1 // little-endian
					len = 1;
					break;
				case 2: // ?x lower 2B
					len = 2;
					break;
				/*case 1: // e?x
					//len = 4; // redundant, it's the default
					//break;*/
				default:
					break;
			}
		}
		// if there is a chance that there is a tainted imm value in the instruction
		unsigned imm_len = isImmSrcInsn (trans.bytes);
		if (imm_len > 0 && isTaint1To1Insn (state, trans.disasm) ) {
			s2e()->getDebugStream () << " >> >> enforceTaints_pre 1to1 imm_len: " << imm_len << " from imm: " << trans.disasm << '\n';
			// if the src addr comes from the imm value segment of the insn
			if ((src_pc - cfg.base_addr) >= (trans.addr + trans.len - imm_len) ) {
				// Intel X86 32b should put all imm values at the end of the insn	
				offset += (src_pc - cfg.base_addr) - (trans.addr + trans.len - imm_len);
				len = 1;
			}
		}
		else {
			s2e()->getDebugStream () << " >> >> enforceTaints_pre !ImmSrc" << '\n';
		}
		writes[i].addr += offset;
		writes[i].len = len;
		s2e()->getDebugStream () << " >> >> enforceTaints_pre offset: " << offset << " len: " << hex (1, len) << '\n';
		if (isTaintScrubbingInsn (state, trans.disasm) ) { 
			scrubAddr (state, writes[i].addr + (is_reg ? 0 : cfg.base_addr), writes[i].len, is_reg);
		}
	}
	
	// now we have reduced the destination bytes, scrubbed all destination bytes, and reduced taints that we need to enforce per destination byte
	// if you don't do all that before hand, then you don't know if you're scrubbing taints that should persist
	for (unsigned i = 0; i < writes.size (); i++) {
		enforceTaintsAddr (state, writes[i], is_reg);
	}
	return;
} // end fn enforceTaintsAddr


void CodeXt::enforceTaintsAddr (S2EExecutionState* state, data_instance write, bool is_reg) {
	uint64_t src_pc = write.next_pc; // there is only ever 1 src addr (1B) when calling enforceTaints // and that byte is from a concretized insn
	uint64_t dst_pc = write.addr;
	if (!is_reg) {
		dst_pc += cfg.base_addr;
	}
	s2e()->getDebugStream () << " >> enforceTaints " << (is_reg ? X86_REG_NAMES[write.is_register] : hex (4, dst_pc) ) << " using taint src: " << hex (4, src_pc) << '\n';
	// get labels that we want to enforce
	// bc src was concretized, simplifyLabeledExpr has already been imposed on it
	std::vector< klee::ref<klee::Expr> > labels = getLabels (read8 (state, src_pc, false) );
	s2e()->getDebugStream () << " >> enforceTaints src: " << hex (4, src_pc) << " found " << labels.size () << " labels" << '\n';
	for (unsigned j = 0; j < labels.size (); j++) {
		// whenever we enforce, use prop_ of the label, may not be necessary, but it may come in handy later
		klee::ref<klee::Expr> e = getPropLabel (state, labels[j]);
		taintAddr (state, dst_pc, write.len, e, is_reg);
		s2e()->getDebugStream () << " >> >> enforceTaints iter done" << '\n';
	} // end foreach label
	return;
} // end fn enforceTaints


void CodeXt::initEventInstance (event_instance_t& e) {
	e.snapshot_idx = 0;
   e.seq_num = 0;
	e.is_register = 0;
   e.addr = 0;
   e.len = 0;
   e.next_pc = 0;
   e.other_pc = 0;
   e.in_range = false;
   e.valid = false;
   e.ti_seq_num = 0;
   e.tb_seq_num = 0;
   //e.bytes;
   //std::string disasm; 
	return;
} // end fn initEventInstance


// snapshot_idx doesn't matter directly, it's purely the pcs and byte values (which is a function of snapshot, pc, len) and snapshot is found via code_map[snapshot_idx]
bool CodeXt::areInsnInstancesEqual (exec_instance i1, exec_instance i2) { 
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


void CodeXt::printExecInstance (exec_instance insn) {
   printEventInstance ((event_instance_t) insn);
} // end fn printExecInstance


void CodeXt::printTransInstance (trans_instance insn) {
   printEventInstance ((event_instance_t) insn);
} // end fn printTransInstance


void CodeXt::printEventInstance (event_instance_t insn) {
   s2e()->getDebugStream () << std::setfill(' ') << std::dec << std::setw (3) << insn.seq_num << ":" << std::setw (3) << insn.ti_seq_num << ":" << std::setw (2) << insn.tb_seq_num << " " << std::setw(2) << insn.len << "B @" << hex (4, insn.addr + cfg.base_addr) << ":";
   // if the insn was out of bounds, then we didn't capture the byte values
   if (!insn.in_range) {
      s2e()->getDebugStream () << " OOB, bytes not captured\n";
      // TODO use the PC and the symbol table to guess where it came from, for instance another internal fn or a standard library
      return;
   }
   
   //uint8_t raw[insn.len];
   unsigned printed_width = 0;
   for (unsigned i = 0; i < insn.len; i++) {
      uint8_t b = insn.bytes[i].byte; //byte (m[insn.snapshot_idx], insn.addr + i);
      //raw[i] = b;
      if (insn.bytes[i].times_used > 1) { // timesUsed (m[insn.snapshot_idx], insn.addr + i) > 1) {
         s2e()->getDebugStream () << "*";
      }
      else {
         s2e()->getDebugStream () << " ";
      }
      printed_width += 1;
      s2e()->getDebugStream () << hex (1, b, 0);
      printed_width += 2;
   }
   while (printed_width < 35) {
      s2e()->getDebugStream () << " ";
      printed_width++;
   }
   if (insn.disasm.length () == 0) {
      s2e()->getDebugStream () << " no disasm stored";
   }
   else {
      s2e()->getDebugStream () << insn.disasm;
   }
   if (!insn.valid) {
      s2e()->getDebugStream () << "  *vestigial*";
   }
   s2e()->getDebugStream () << " nextPC: " << hex (4, insn.next_pc);
   //if (insn.other_pc != 0x00000000 && insn.other_pc != insn.next_pc) s2e()->getDebugStream () << " jmpPc: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.other_pc;
   s2e()->getDebugStream () << '\n';
   return;
} // end fn printEventInstance

/*
void CodeXt::printOOBDebug (S2EExecutionState* state) {
   DECLARE_PLUGINSTATE (CodeXtState, state);
   // print the trans_trace
   printTransTrace (plgState->trans_trace); //, plgState->code_map);
   //mapExecs ();
   //printMemMap (plgState->code_map, cfg.base_addr);
   return;
} // end fn printOOBDebug
*/

void CodeXt::printOOBInsn (S2EExecutionState* state, trans_instance insn, unsigned num_oob) {
   // there is no memory snapshot, this is taken directly from memory
   // get the raw insn bytes from the guest memory
   uint8_t raw[insn.len];
   // NOTE that in order to work, the original pc must have been greater in value than cfg.base_addr
   if (!readMemory (state, insn.addr + cfg.base_addr, raw, insn.len) ) {
      s2e()->getWarningsStream (state) << "!! ERROR: could not read guest memory @" << hex (4, insn.addr + cfg.base_addr) << " to gather ASM insns, pOOBI\n";
      terminateStateEarly_wrap (state, std::string ("eliminated a state with an invalid read"), true);
      return;
   }
   s2e()->getDebugStream () << std::setfill(' ') << std::dec << std::setw (3) << insn.ti_seq_num << ":" << std::setw (3) << num_oob << " " << std::setw(2) << insn.len << "B @" << hex (4, insn.addr + cfg.base_addr) << ":";
   printInsn_raw (raw, insn.len, true);
   s2e()->getDebugStream () << " nextPC: " << hex (4, insn.next_pc);
   //if (insn.other_pc != 0x00000000 && insn.other_pc != insn.next_pc) s2e()->getDebugStream () << " jmpPc: 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << std::hex << insn.other_pc;
   s2e()->getDebugStream () << '\n';
   return;
} // end fn printOOBInsn


void CodeXt::printWriteInstance (data_instance w) {
   s2e()->getDebugStream () << std::setfill(' ') << std::dec << std::setw (3) << w.seq_num << " by:" << hex (4, w.other_pc) << " wrote " << std::setfill(' ') << std::dec << std::setw(2) << w.len << "B @" << hex (4, (w.addr + cfg.base_addr) ) << ":";
   
   s2e()->getDebugStream () << " ";
   // if the insn was out of bounds, then we didn't capture the byte values
   if (!w.in_range) {
      s2e()->getDebugStream () << "OOB ";
   }
   
   for (unsigned i = 0; i < w.bytes.size (); i++) {
      s2e()->getDebugStream () << hex (1, w.bytes[i].byte, 0) << " ";
   }
   s2e()->getDebugStream () << '\n';
   return;
} // end fn printWriteInstance 


void CodeXt::setSyscNames () {
	SyscNames[0] = "invalid";
	SyscNames[1] = "exit";
	SyscNames[2] = "fork";
	SyscNames[3] = "read";
	SyscNames[4] = "write";
	SyscNames[5] = "open";
	SyscNames[6] = "close";
	SyscNames[7] = "waitpid";
	SyscNames[8] = "creat";
	SyscNames[9] = "link";
	SyscNames[10] = "unlink";
	SyscNames[11] = "execve";
	SyscNames[12] = "chdir";
	SyscNames[13] = "time";
	SyscNames[14] = "mknod";
	SyscNames[15] = "chmod";
	SyscNames[16] = "lchown16";
	SyscNames[17] = "unknown";
	SyscNames[18] = "stat";
	SyscNames[19] = "lseek";
	SyscNames[20] = "getpid";
	SyscNames[21] = "mount";
	SyscNames[22] = "oldumount";
	SyscNames[23] = "setuid16";
	SyscNames[24] = "getuid16";
	SyscNames[25] = "stime";
	SyscNames[26] = "ptrace";
	SyscNames[27] = "alarm";
	SyscNames[28] = "fstat";
	SyscNames[29] = "pause";
	SyscNames[30] = "utime";
	SyscNames[31] = "unknown";
	SyscNames[32] = "unknown";
	SyscNames[33] = "access";
	SyscNames[34] = "nice";
	SyscNames[35] = "unknown";
	SyscNames[36] = "sync";
	SyscNames[37] = "kill";
	SyscNames[38] = "rename";
	SyscNames[39] = "mkdir";
	SyscNames[40] = "rmdir";
	SyscNames[41] = "dup";
	SyscNames[42] = "pipe";
	SyscNames[43] = "times";
	SyscNames[44] = "unknown";
	SyscNames[45] = "brk";
	SyscNames[46] = "setgid16";
	SyscNames[47] = "getgid16";
	SyscNames[48] = "signal";
	SyscNames[49] = "geteuid16";
	SyscNames[50] = "getegid16";
	SyscNames[51] = "acct";
	SyscNames[52] = "umount";
	SyscNames[53] = "unknown";
	SyscNames[54] = "ioctl";
	SyscNames[55] = "fcntl";
	SyscNames[56] = "unknown";
	SyscNames[57] = "setpgid";
	SyscNames[58] = "unknown";
	SyscNames[59] = "olduname";
	SyscNames[60] = "umask";
	SyscNames[61] = "chroot";
	SyscNames[62] = "ustat";
	SyscNames[63] = "dup2";
	SyscNames[64] = "getppid";
	SyscNames[65] = "getpgrp";
	SyscNames[66] = "setsid";
	SyscNames[67] = "sigaction";
	SyscNames[68] = "sgetmask";
	SyscNames[69] = "ssetmask";
	SyscNames[70] = "setreuid16";
	SyscNames[71] = "setregid16";
	SyscNames[72] = "sigsuspend";
	SyscNames[73] = "sigpending";
	SyscNames[74] = "sethostname";
	SyscNames[75] = "setrlimit";
	SyscNames[76] = "old_getrlimit";
	SyscNames[77] = "getrusage";
	SyscNames[78] = "gettimeofday";
	SyscNames[79] = "settimeofday";
	SyscNames[80] = "getgroups16";
	SyscNames[81] = "setgroups16";
	SyscNames[82] = "old_select";
	SyscNames[83] = "symlink";
	SyscNames[84] = "lstat";
	SyscNames[85] = "readlink";
	SyscNames[86] = "uselib";
	SyscNames[87] = "swapon";
	SyscNames[88] = "reboot";
	SyscNames[89] = "old_readdir";
	SyscNames[90] = "old_mmap";
	SyscNames[91] = "munmap";
	SyscNames[92] = "truncate";
	SyscNames[93] = "ftruncate";
	SyscNames[94] = "fchmod";
	SyscNames[95] = "fchown16";
	SyscNames[96] = "getpriority";
	SyscNames[97] = "setpriority";
	SyscNames[98] = "unknown";
	SyscNames[99] = "statfs";
	SyscNames[100] = "fstatfs";
	SyscNames[101] = "ioperm";
	SyscNames[102] = "socketcall";
	SyscNames[103] = "syslog";
	SyscNames[104] = "setitimer";
	SyscNames[105] = "getitimer";
	SyscNames[106] = "newstat";
	SyscNames[107] = "newlstat";
	SyscNames[108] = "newfstat";
	SyscNames[109] = "uname";
	SyscNames[110] = "iopl";
	SyscNames[111] = "vhangup";
	SyscNames[112] = "unknown";
	SyscNames[113] = "vm86old";
	SyscNames[114] = "wait4";
	SyscNames[115] = "swapoff";
	SyscNames[116] = "sysinfo";
	SyscNames[117] = "ipc";
	SyscNames[118] = "fsync";
	SyscNames[119] = "sigreturn";
	SyscNames[120] = "clone";
	SyscNames[121] = "setdomainname";
	SyscNames[122] = "newuname";
	SyscNames[123] = "modify_ldt";
	SyscNames[124] = "adjtimex";
	SyscNames[125] = "mprotect";
	SyscNames[126] = "sigprocmask";
	SyscNames[127] = "unknown";
	SyscNames[128] = "init_module";
	SyscNames[129] = "delete_module";
	SyscNames[130] = "unknown";
	SyscNames[131] = "quotactl";
	SyscNames[132] = "getpgid";
	SyscNames[133] = "fchdir";
	SyscNames[134] = "bdflush";
	SyscNames[135] = "sysfs";
	SyscNames[136] = "personality";
	SyscNames[137] = "unknown";
	SyscNames[138] = "unknown";
	SyscNames[139] = "unknown";
	SyscNames[140] = "unknown";
	SyscNames[141] = "unknown";
	SyscNames[142] = "select";
	SyscNames[143] = "unknown";
	SyscNames[144] = "unknown";
	SyscNames[145] = "unknown";
	SyscNames[146] = "unknown";
	SyscNames[147] = "unknown";
	SyscNames[148] = "unknown";
	SyscNames[149] = "sysctl";
	SyscNames[150] = "mlock";
	SyscNames[151] = "munlock";
	SyscNames[152] = "unknown";
	SyscNames[153] = "unknown";
	SyscNames[154] = "unknown";
	SyscNames[155] = "unknown";
	SyscNames[156] = "unknown";
	SyscNames[157] = "unknown";
	SyscNames[158] = "unknown";
	SyscNames[159] = "unknown";
	SyscNames[160] = "unknown";
	SyscNames[161] = "unknown";
	SyscNames[162] = "unknown";
	SyscNames[163] = "unknown";
	SyscNames[164] = "unknown";
	SyscNames[165] = "unknown";
	SyscNames[166] = "unknown";
	SyscNames[167] = "unknown";
	SyscNames[168] = "poll";
	SyscNames[169] = "unknown";
	SyscNames[170] = "unknown";
	SyscNames[171] = "unknown";
	SyscNames[172] = "unknown";
	SyscNames[173] = "unknown";
	SyscNames[174] = "unknown";
	SyscNames[175] = "unknown";
	SyscNames[176] = "unknown";
	SyscNames[177] = "unknown";
	SyscNames[178] = "unknown";
	SyscNames[179] = "unknown";
	SyscNames[180] = "unknown";
	SyscNames[181] = "unknown";
	SyscNames[182] = "unknown";
	SyscNames[183] = "unknown";
	SyscNames[184] = "unknown";
	SyscNames[185] = "unknown";
	SyscNames[186] = "unknown";
	SyscNames[187] = "unknown";
	SyscNames[188] = "unknown";
	SyscNames[189] = "unknown";
	SyscNames[190] = "unknown";
	SyscNames[191] = "unknown";
	SyscNames[192] = "mmap2";
	SyscNames[193] = "unknown";
	SyscNames[194] = "unknown";
	SyscNames[195] = "stat64";
	SyscNames[196] = "lstat64";
	SyscNames[197] = "fstat64";
	SyscNames[198] = "unknown";
	SyscNames[199] = "getuid";
	SyscNames[200] = "setuid";
	SyscNames[201] = "unknown";
	SyscNames[202] = "unknown";
	SyscNames[203] = "unknown";
	SyscNames[204] = "unknown";
	SyscNames[205] = "unknown";
	SyscNames[206] = "unknown";
	SyscNames[207] = "unknown";
	SyscNames[208] = "unknown";
	SyscNames[209] = "unknown";
	SyscNames[210] = "unknown";
	SyscNames[211] = "unknown";
	SyscNames[212] = "unknown";
	SyscNames[213] = "setuid";
	SyscNames[214] = "setgid";
	SyscNames[215] = "unknown";
	SyscNames[216] = "unknown";
	SyscNames[217] = "unknown";
	SyscNames[218] = "unknown";
	SyscNames[219] = "unknown";
	SyscNames[220] = "unknown";
	SyscNames[221] = "unknown";
	SyscNames[222] = "unknown";
	SyscNames[223] = "unknown";
	SyscNames[224] = "unknown";
	SyscNames[225] = "unknown";
	SyscNames[226] = "unknown";
	SyscNames[227] = "unknown";
	SyscNames[228] = "unknown";
	SyscNames[229] = "unknown";
	SyscNames[230] = "unknown";
	SyscNames[231] = "unknown";
	SyscNames[232] = "unknown";
	SyscNames[233] = "unknown";
	SyscNames[234] = "unknown";
	SyscNames[235] = "unknown";
	SyscNames[236] = "unknown";
	SyscNames[237] = "unknown";
	SyscNames[238] = "unknown";
	SyscNames[239] = "unknown";
	SyscNames[240] = "unknown";
	SyscNames[241] = "unknown";
	SyscNames[242] = "unknown";
	SyscNames[243] = "set_thread_area";
	SyscNames[244] = "get_thread_area";
	SyscNames[245] = "unknown";
	SyscNames[246] = "unknown";
	SyscNames[247] = "unknown";
	SyscNames[248] = "unknown";
	SyscNames[249] = "unknown";
	SyscNames[250] = "unknown";
	SyscNames[251] = "unknown";
	SyscNames[252] = "unknown";
	SyscNames[253] = "unknown";
	SyscNames[254] = "unknown";
	SyscNames[255] = "unknown";
	SyscNames[256] = "unknown";
	return;
} // end fn setSyscNames


std::string CodeXt::printSyscName (unsigned int num) {
	std::ostringstream os;
	os << (num <= 256 ? SyscNames[num] : "unknown");
	std::string ret (os.str () );
	//return os; 
	return ret;
} // end fn printSyscNames

   
void CodeXt::printSyscallInstance (Syscall s) {
   //s2e()->getDebugStream () << " >>    Printing syscall:";
   s2e()->getDebugStream () << std::dec << std::setw(4) << std::setfill (' ') << s.seq_num << ": @" << hex (4, s.addr) << ":  sysc_num: " << (uint32_t) s.num << "(" << hex (4, (uint32_t) s.num) << ")[" << printSyscName (s.num) << "] ";
	
   if (s.success) {
      s2e()->getDebugStream () << "match ";
   }
   else {
      s2e()->getDebugStream () << "frag  ";
   }
   s2e()->getDebugStream () << '\n';
   s2e()->getDebugStream () << " >>       preState:"; 
   printX86State (s.preState);
   //s2e()->getDebugStream << " >>   postState:";
   //printX86State (s.postState);
   return;
} // end fn printSyscallInstance


// is needle a subset or equal to haystack
// equal is not byte for byte, it ignores OOB and invalid insns
// Executed Insns are only traced by hooked set on IOB onsn upon their translation
// Thus all Exec'ed are valid and in range.
bool CodeXt::isExecTraceSubset (Exec_Trace needle, Exec_Trace haystack) { 
   if (needle.insns.size () == 0) {
      return true;
   }
   if (haystack.insns.size () == 0 || haystack.insns.size () < needle.insns.size () ) {
      return false;
   }
   // at this point haystack is always larger than needle, and both are unsigned (>0)
   // thus haystack-needle >= 0
   // for each offset in haystack except for a suffix of length less than needle
   unsigned max_i = haystack.insns.size () - needle.insns.size () + 1;
   for (unsigned i = 0; i < max_i; i++) {
      unsigned j = 0;
      s2e()->getDebugStream () << " >> !!!! 0 ("<<i<<","<<j<<")\n";
      while (j < needle.insns.size () && (i+j) < haystack.insns.size () && areInsnInstancesEqual (needle.insns[j], haystack.insns[i+j]) ) {
         s2e()->getDebugStream () << " >> !!!! 1 ("<<i<<","<<j<<")\n";
         j++;
         if (j == needle.insns.size () ) {
            return true;
         }
      }
   }
   return false;
} // end fn isExecTraceSubset


void CodeXt::printExecTrace (Exec_Trace e) {
   s2e()->getDebugStream () << " >> Printing Exec_Trace (instructions in order of execution)\n";
   for (unsigned i = 0; i < e.insns.size (); i++) {
      s2e()->getDebugStream () << " >>    ";
      printExecInstance (e.insns[i]);
   }
   return;
} // end fn printExecTrace


void CodeXt::printTransTrace (Trans_Trace t) {
   s2e()->getDebugStream () << " >> Printing Trans_Trace (instructions in order of translation)\n";
   for (unsigned i = 0; i < t.insns.size (); i++) {
      s2e()->getDebugStream () << " >>    ";
      printTransInstance (t.insns[i]);
   }
   return;
} // end fn printTransTrace


// works bc oDMA happens before oEI. 
// If not the case, then you must either translate the instruction to decipher the write addr or set a flag for the next oDMA, if matches this writer addr, then swap in our last_fpu_pc value.
uint64_t CodeXt::findWriteAddr (uint64_t writer, Data_Trace t) {
   if (t.writes.size () == 0) {
      return 0;
   }
   //s2e()->getDebugStream () << " >> oEI looking in data_trace for FPU stenv pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << writer << '\n';
   // search write_trace backwards looking for writer_pc, upon match return its addr
   // note that 1 insn instance may write many 32/64b times, so you need to catch the earliest write in the latest set of the writes
   for (int i = (t.writes.size () - 1); i >= 0; i--) {
      //s2e()->getDebugStream () << " >> oEI compare: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << writer << " to 0x" << t.writes[i].other_pc << '\n';
      // find the first write addr of the most recent batch of writes for a particular pc
      if ((i == 0 && writer == t.writes[i].other_pc) || (i > 0 && writer == t.writes[i].other_pc && writer != t.writes[i-1].other_pc) ) {
         //s2e()->getDebugStream () << " >> oEI match target was: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << t.writes[i].addr + cfg.base_addr << '\n';
         return t.writes[i].addr + cfg.base_addr;
      }
   }
   return 0;
} // end fn findWriteAddr


void CodeXt::printDataTrace (Data_Trace d) {
   //if (d.writes.size () > 0) {
   s2e()->getDebugStream () << " >> Printing Data_Trace (bytes written in order of write)\n";
   for (unsigned i = 0; i < d.writes.size (); i++) {
      s2e()->getDebugStream () << " >>    ";
      printWriteInstance (d.writes[i]/*, m, i, true*/);
   }
   //}
   //else {
    //  s2e()->getDebugStream () << " >> No entries in Data_Trace to print\n";
   //}
   return;
} // end fn printDataTrace


void CodeXt::printCallTrace (Syscall_Trace t) {
   s2e()->getDebugStream () << " >> Printing Syscall_Trace (" << std::dec << t.size () << " ordered system calls in this fragment)\n";
   for (unsigned i = 0; i < t.size (); i++) {
      s2e()->getDebugStream () << " >>    " << std::setfill (' ') << std::setw (2) << i << ": ";
      printSyscallInstance (t[i]);
   }
   s2e()->getDebugStream () << '\n';
   return;
} // end fn printCallTrace


void CodeXt::printInsn_raw (uint8_t* raw, unsigned raw_len, bool doDisasm) {
   unsigned printed_width = 0;
   for (unsigned i = 0; i < raw_len; i++) {
      s2e()->getDebugStream () << " ";
      printed_width += 1;
      s2e()->getDebugStream () << hex (1, raw[i], 0);
      printed_width += 2;
   }
   while (printed_width < 18) {
      s2e()->getDebugStream () << " ";
      printed_width++;
   }
   if (doDisasm) {
      printDisasm (raw, raw_len);
   }
   return;
} // end fn printInsn_raw


void CodeXt::printDisasm (uint8_t* raw, unsigned len) {
   printDisasmSingle (raw, len);
}  // end fn printDisasm


// use libudis to give human readable output of ASM
void CodeXt::printDisasmSingle (uint8_t* raw, unsigned len) {
   ud_t ud_obj;
   ud_init (&ud_obj);
   ud_set_mode (&ud_obj, 32);
   ud_set_syntax (&ud_obj, UD_SYN_INTEL);
   
   ud_set_input_buffer(&ud_obj, raw, len);
   
   unsigned insn_len = 0;
   if ((insn_len = ud_disassemble (&ud_obj) ) != len) {
      s2e()->getDebugStream () << "disasm didn't do all insn bytes: " << insn_len << "/" << len;
      return;
   }
   char buf[64];
   snprintf (buf, sizeof (buf), " %-24s", ud_insn_asm (&ud_obj) );
   s2e()->getDebugStream () << buf;

   return;
} // end fn printDisasm_viaLib


std::string CodeXt::getDisasmSingle (uint8_t* raw, unsigned len) {
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
   while (disasm[0] == ' ') {
   	disasm.erase (0, 1);
   }
   return disasm;
} // end fn getDisasmSingle


std::string CodeXt::getDisasmSingle (std::vector<struct mem_byte> bytes) {
   uint8_t raw[bytes.size ()];
   for (unsigned i = 0; i < bytes.size (); i++) {
      raw[i] = bytes[i].byte;
   }
   return getDisasmSingle (raw, bytes.size () );
} // end fn getDisasmSingle

   
void CodeXt::mapExecs (Mem_map& m, Exec_Trace e) {
   if (e.insns.size () == 0) {
      // there were no instructions executed, nothing to do here
      return;
   }
   
   // there should be at least no existing snapshots
   if (m.snaps.size () != 0) {
      s2e()->getDebugStream () <<  "!! ERROR: code_map is wrong size (" << m.snaps.size () << ")\n";
      return;
      //terminateStateEarly_wrap (state, std::string ("mapExecs, code_map wrong size"), false);
   }
   
	uint32_t map_base = cfg.base_addr;
	uint32_t map_len  = cfg.byte_len;
   if (cfg.elf_mode) {
		return; // there is an error in the appendSnapshot->vector.resize bad alloc
		/*
		uint32_t min_addr = 0xffffffff;
		uint32_t max_addr = 0x00000000;
   	for (unsigned i = 0; i < e.insns.size (); i++) {
			if (e.insns[i].addr > max_addr) max_addr = e.insns[i].addr;
			if (e.insns[i].addr < min_addr) min_addr = e.insns[i].addr;
		}
		map_base = min_addr;
		map_len  = max_addr - min_addr + 1;*/
   }
	
	
	
   // foreach IOB execution
   for (unsigned i = 0; i < e.insns.size (); i++) {
      exec_instance* ei = &(e.insns[i]);
      bool valid = true;
      if (!ei->in_range) { // alt: if (!isInShell (state, ei->addr) ) {
         valid = false;
      }
      
      //if (isInsnRepeat (e.insns[i], plgState->trans_trace.insns[plgState->trans_trace.last_valid]) { valid = false; }
      //if (ignorable preface/first instructions, such as '90 90') { valid = false; }
      
      // if we want to use this insn
      if (valid) {
         // if this is the first instruction that is in range...
         if (m.snaps.size () == 0) {
            // at least 1 IOB instruction exists, so we will need a snapshot for it
            appendSnapshot (m, map_len);
            // m.size is now 1
         }
         
         // see if this will need a new snapshot
         // check to make sure that this insn isn't diff at any bytes prev called
         // saves peddling back on execution path, ie redoing beginning bytes (decrementing times_used and then putting into new snapshot) if changed byte is in middle of insn
         bool changed = false;
         for (unsigned j = 0; !changed && j < ei->bytes.size (); j++) {
            // if the most recent snapshot mem_byte has been used before (it can't be diff if it's never been used)
            if (timesUsed (m.snaps.back (), ei->addr + j - map_base) > 0) {
               // if the value of the byte we are attempting to record is diff than the one currently stored in the most recent snapshot
               uint8_t b = byte (m.snaps.back (), ei->addr + j - map_base);
               if (b != ei->bytes[j].byte) {
                  // byte has been modified, we need a new snapshot...
                  //s2e()->getDebugStream () << " >> A byte at offset " << std::dec << i << " has been changed, times_exec'ed before now: " << t << ", orig val: " << std::hex << b << ", new val: " << ei->bytes[j].byte << '\n';
                  m.snaps.back().density = m.snaps.back().num_used_bytes / (m.snaps.back().max_addr - m.snaps.back().min_addr + 1);
                  appendSnapshot (m, map_len);
                  changed = true; // end forloop
               }
            }
         } // end see if any bytes have been changed
         
         // so now we are either (if changed or never yet written) writing bytes to a new snapshot or (if not changed) just timesUsedInc
         // store bytes into map
         for (unsigned j = 0; j < ei->bytes.size (); j++) {
            if (changed || timesUsed (m.snaps.back (), ei->addr + j - map_base) == 0) {
               byteWrite (m.snaps.back (), ei->addr + j - map_base, ei->bytes[j].byte);
               m.snaps.back ().num_used_bytes++;
               validate (m.snaps.back (), ei->addr + j - map_base);
               m.snaps.back().num_valid_bytes++;
            }
            timesUsedInc (m.snaps.back (), ei->addr + j - map_base);
         }
         
         // update the min and max addr
         if (ei->addr - map_base < m.snaps.back().min_addr) {
            m.snaps.back().min_addr = ei->addr - map_base;
         }
         if (ei->addr + ei->len - map_base > m.snaps.back().max_addr) {
            m.snaps.back().max_addr = ei->addr + ei->len - map_base;
         }
      } // end if we want to look at this insn
   } // end foreach exec'ed insn
	
	m.name = "Exec_map";
   
   return;
} // end fn mapExecs
   

void CodeXt::mapWrites (Mem_map& m, Data_Trace d) {
   // there should be at least 1 map of the initial memory
   if (m.snaps.size () != 1) {
      s2e()->getDebugStream () <<  "!! ERROR: data_map is wrong size (" << m.snaps.size () << ")\n";
      return;
      //terminateStateEarly_wrap (state, std::string ("mapWrites, data_map wrong size"), false);
   }
   
   // assumes that m[0] is the init'ed snapshot of entire memory space/dump
   m.snaps.front().density = 0;
   m.snaps.front().num_used_bytes = 0;

   // if there are no writes, then there is no need to do anything
   if (d.writes.size () == 0) {
      m.snaps.front().min_addr = 0;
      m.snaps.front().max_addr = 0;
      return;
   }
   // at this point we can assume that there is at least 1 write

   // last_write_seq_num is used for clustering writes, if writes are too many instructions apart, then a new snapshot is added regardless if byte values changed
   uint64_t last_write_seq_num = 0;
   // for each write
   for (unsigned i = 0; i < d.writes.size (); i++) {
      if (d.writes[i].in_range) {
         // for each byte within write, store into snapshot if equal or empty, otherwise make new snapshot and store there
         for (unsigned j = 0; j < d.writes[i].bytes.size (); j++) {
            bool byte_changed = false;
            bool diff_cluster = false;
            bool first_mapping = false;
            uint64_t addr = d.writes[i].addr + j;
            
            //s2e()->getDebugStream () << " >> DEBUG mapWrites d.writes[" << std::dec << i << "].addr + " << j << ": " << std::hex << addr << '\n'; 
            
            // if this byte is written to and we don't have a snapshot to store it in, regardless if it's value is diff than original
            if (m.snaps.size () == 1 && timesUsed (m.snaps.back (), addr) == 0) {
               last_write_seq_num = d.writes[i].seq_num;
               first_mapping = true;
            }
            //byte_changed = hasByteChanged (d.writes[i].bytes[j].byte, m, addr);
            else if (timesUsed (m.snaps.back (), addr) != 0 && byte (m.snaps.back (), addr) != d.writes[i].bytes[j].byte) {
               byte_changed = true;
            }
            //same_cluster = hasClusterChanged (d.writes[i].seq_num, plgState->last_write_seq_num);
            else if (m.snaps.size () > 1 && (d.writes[i].seq_num - last_write_seq_num) >= cfg.cluster_writes_by) { // 10
               diff_cluster = true;
            }
            // else use the same snapshot
            
            /* there are 3 actions
              * 1) inc times used (keep existing snapshot but do not write value to it) <- always done
              * 2) make a new snapshot (see below)
              * 3) write value to existing snapshot
              * 
              * there are three reasons to make a new snapshot
              * 1) the byte value has changed and timesUsed != 0
              * 2) the clustering difference is too great
              * 3) timesUsed == 0 but we've never mapped a write yet
              * 
              * conversely reasons to keep using currently snapshot
              * 1) byte is the same
              * 2) timesUsed == 0 and there's a snapshot to map into
              * 3) clustering difference within range
              * 
              * there are reasons to write value
              * 1) you made a new snapshot
              * 2) the byte in the snapshot is not used (timesUsed == 0) (detectable once you make a new snapshot)
              */
            //s2e()->getDebugStream () << " >> DEBUG mapWrites byte_changed " << std::dec << byte_changed << " same_cluster " << std::dec << same_cluster << " append_snapshot " << append_snapshot << " timesUsed " << timesUsed (m.back (), addr) << " seq_num " << d.writes[i].seq_num << " last_write_seq_num " << last_write_seq_num << '\n';

            // if this is the first mapping, then we need to make a snapshot for it, but m[0] (m.front) doesn't have any stats info, nor should the density be set yet (save that for the end)
            if (!first_mapping) { 
               // make sure that current snapshot has min and max set properly
               // get current snapshot stats, ie density
               if (m.snaps.back().num_used_bytes == 0 || m.snaps.back().max_addr < m.snaps.back().min_addr) {
                  s2e()->getDebugStream () << "!! ERROR: appending snapshot when something wrong with current: num_used_bytes " << std::dec << m.snaps.back().num_used_bytes << " max_addr " << m.snaps.back().max_addr << " min_addr " << m.snaps.back().min_addr << '\n';
                  // terminateStateEarly_wrap (state, std::string ("bad snapshot in data map"), false);
                  return;
               }
               m.snaps.back().density = m.snaps.back().num_used_bytes / (m.snaps.back().max_addr - m.snaps.back().min_addr + 1);
            }
            if (byte_changed || diff_cluster || first_mapping) {
               appendSnapshot (m, cfg.byte_len);
            } // end if appendSnapshot
            
            if (timesUsed (m.snaps.back (), addr) == 0) {
               byteWrite (m.snaps.back (), addr, d.writes[i].bytes[j].byte);
               if (timesUsed (m.snaps.back (), addr) == 0) { 
                  m.snaps.back().num_used_bytes++;
                  validate (m.snaps.back (), addr);
                  m.snaps.back().num_valid_bytes++;
               }
               // store min and max_addr
               if (addr < m.snaps.back().min_addr) {
                  m.snaps.back().min_addr = addr;
               }
               if (addr > m.snaps.back().max_addr) {
                  m.snaps.back().max_addr = addr;
               }
            }
            
            // consider adding if timesUsed == 0 then write it anyways, it might be weird to have timesUsed > 0 and no value appear, regardless if it is the same as the write to the previous snapshot
            timesUsedInc (m.snaps.back (), addr);
            if (timesUsed (m.snaps.front (), addr) == 0) {
               m.snaps.front().num_used_bytes++;
               validate (m.snaps.front (), addr);
               m.snaps.front().num_valid_bytes++;
            }
            timesUsedInc (m.snaps.front (), addr);
            // store min and max_addr
            if (addr < m.snaps.front().min_addr) {
               m.snaps.front().min_addr = addr;
            }
            if (addr > m.snaps.front().max_addr) {
               m.snaps.front().max_addr = addr;
            }
            last_write_seq_num = d.writes[i].seq_num;
         } // end for each data write's byte
      } // end if in range
   } // end for each data write
   // do assert on num_used_bytes > 0 && max > min
   m.snaps.front().density = m.snaps.front().num_used_bytes / (m.snaps.front().max_addr - m.snaps.front().min_addr + 1);
   
	m.name = "Write_map";
	
   return;
} // end fn mapWrites


void CodeXt::mapTaints (S2EExecutionState* state, std::vector<Mem_map>& ms) {
	simplifyMemory (state);
	// for each taint label
	unsigned label_cnt = 0;
	for (unsigned i = 0; i < cfg.symb_vars.size (); i++) {
		for (unsigned j = 0; j < cfg.symb_vars[i].labels.size (); j++) {
			s2e()->getDebugStream () << '\n';
			s2e()->getDebugStream () << " >> mapTaints, label[" << label_cnt << "]: " << cfg.symb_vars[i].labels[j] << '\n';
			// for each byte in memory see if not constant and if tainted by this loop's label
			Mem_map taint_map = mapTaint (state, cfg.symb_vars[i].labels[j]);
			// print a map with byte values to indicate which bytes are tainted
			printMemMap (taint_map, cfg.base_addr);
			label_cnt++;
			ms.push_back (taint_map);
		}
	}
	return;
} // end fn mapTaints


Mem_map CodeXt::mapTaint (S2EExecutionState* state, klee::ref<klee::Expr> label) {
	Mem_map m;
	// initialize/append an empty snapshot
   appendSnapshot (m, cfg.byte_len);
	// for each byte in memory, if ! constant and is tainted with label, then store into snapshot
	std::string label_str = getLabelStr (label);
	label_str = trimLabelStr (label_str);
	s2e()->getDebugStream () << " >> Printing Taint_Trace (in order of address) for label: " << label_str << '\n';
	m.name = label_str;
   for (unsigned i = 0; i < cfg.byte_len; i++) {
		klee::ref<klee::Expr> e = read8 (state, cfg.base_addr + i, false);
		if (doesExprContainLabel (e, label_str) ) {
			//s2e()->getDebugStream () << " >> >> mapTaint[" << i << "] " << hex (4, cfg.base_addr + i) << " found non-constantExpr: " << e << '\n';
			uint8_t b;
			readMemory (state, cfg.base_addr + i, (void*) &b, 1);
			//s2e()->getDebugStream () << " >> >> mapTaint[" << i << "] concretized to: " << hex (1, b) << '\n';
			s2e()->getDebugStream () << " >>\t@" << hex (4, cfg.base_addr + i) << ": " << hex (1, b) << '\n';
			byteWrite (m.snaps.back (), i, b);
			validate (m.snaps.back (), i);
			timesUsedInc (m.snaps.back (), i);
			m.snaps.back().num_used_bytes++;
   		m.snaps.back().num_valid_bytes++;
			if (i < m.snaps.back().min_addr) {
				m.snaps.back().min_addr = i;
			}
			if (i > m.snaps.back().max_addr) {
				m.snaps.back().max_addr = i;
			}
   	}
   }
   m.snaps.back().density = m.snaps.back().num_used_bytes / (m.snaps.back().max_addr - m.snaps.back().min_addr + 1);
	return m;
} // end fn mapTaint


void CodeXt::printMem_raw (uint8_t* raw, unsigned raw_len, uint64_t base) {
   unsigned curr_addr, end_addr, i, j;
   char buf[1024];
   
   //unsigned min_addr = base;
   //unsigned max_addr = base + raw_len;
   
   // align for print out
   curr_addr = base & 0xfffffff0;
   end_addr = base + raw_len - 1;
   //s2e()->getDebugStream () << " >>    The density (0 to 1) of this state's path is (" << std::dec << s.num_valid_bytes << "/" << (end_addr - min_addr + 1) << ") = " << s.density << '\n';
   //snprintf (buf, sizeof (buf), " >>    Mem_map start_addr: 0x%08x, length: %uB, end_addr: 0x%08x\n", (unsigned) base, raw_len, end_addr);
   s2e()->getDebugStream () << " >>    Mem_map start_addr: " << hex (4, base) << ", length: " << raw_len << "B, end_addr: " << hex (4, end_addr) << '\n';//", (unsigned) base, raw_len, end_addr);
   //s2e()->getDebugStream () << buf;
   // for loop printing out dump in words with address grid like in gdb
   s2e()->getDebugStream () << "           0 1 2 3  4 5 6 7  8 9 a b  c d e f   ASCII\n";
   // for each row
	// needs a special conditional in case of 1B maps with the valid byte at a 0x???????0 addr (eg base & 0xfffffff0 == base && min_addr == max_addr)
   while (curr_addr < end_addr || (curr_addr == base && base == end_addr) ) {
      snprintf (buf, sizeof (buf), "0x%08x", curr_addr);
      s2e()->getDebugStream () << buf;
      char ascii_out[17];
      memset (ascii_out, ' ', 16);
      ascii_out[16] = '\0';
      // for each of the 4 words in the row
      for (i = 0; i < 4; i++) {
         snprintf (buf, sizeof (buf), " ");
         s2e()->getDebugStream () << buf;
         // for each of the 4 bytes in the word
         for (j = 0; j < 4; j++) {
            if (curr_addr < base) {
               snprintf (buf, sizeof (buf), "  ");
               s2e()->getDebugStream () << buf;
            }
            else if (curr_addr <= end_addr) {
               char tmp = raw[curr_addr - base];
               snprintf (buf, sizeof (buf), "%02x", (unsigned int) tmp & 0x000000ff);
               s2e()->getDebugStream () << buf;
               ascii_out[(i * 4) + j] = isprint (tmp) ? tmp : '.';
            }
            else {
               s2e()->getDebugStream () << "  ";
            }
            curr_addr++;
         } // end for each byte
      } // end for each word
      s2e()->getDebugStream () << "  " << ascii_out << '\n';
   } // end while each row
   s2e()->getDebugStream () << '\n';
   
   return;
} // end fn printMem_raw


void CodeXt::printSnapshot (Snapshot s, uint64_t base, bool force_print) {
   // Print dump as already coded using snapshot.mem_bytes[i].byte
   unsigned curr_addr, end_addr, i, j;
   char buf[1024];
   
   unsigned min_addr = s.min_addr + base;
   unsigned max_addr = s.max_addr + base;
    
   // align for print out
   curr_addr = min_addr & 0xfffffff0;
   end_addr = max_addr;
   s2e()->getDebugStream () << " >>    The density (0 to 1) of this state's path is (" << std::dec << s.num_valid_bytes << "/" << (end_addr - min_addr + 1) << ") = " << s.density << '\n';
   //snprintf (buf, sizeof (buf), " >>    Mem_map start_addr: 0x%08x, length: %uB, valid bytes: %u, used bytes: %u, range: %uB, end_addr: 0x%08x\n", min_addr, (unsigned) (s.max_addr - s.min_addr + 1), s.num_valid_bytes, s.num_used_bytes, end_addr - min_addr + 1, end_addr);
   s2e()->getDebugStream () << " >>    Mem_map start_addr: " << hex (4, min_addr) << ", length: " << (s.max_addr - s.min_addr + 1) << "B, valid bytes: " << s.num_valid_bytes << ", used bytes: " << s.num_used_bytes << ", range: " << (end_addr - min_addr + 1) << "B, end_addr: " << hex (4, end_addr) << '\n';
   //s2e()->getDebugStream () << buf;
   // for loop printing out dump in words with address grid like in gdb
   s2e()->getDebugStream () << "           0 1 2 3  4 5 6 7  8 9 a b  c d e f   ASCII\n";
   // for each row
	// needs a special conditional in case of 1B maps with the valid byte at a 0x???????0 addr (eg s.min_addr & 0xfffffff0 == s.min_addr && s.min_addr == s.max_addr)
   while (curr_addr < end_addr || (curr_addr == min_addr && min_addr == max_addr) ) {
      snprintf (buf, sizeof (buf), "0x%08x", curr_addr);
      s2e()->getDebugStream () << buf;
      char ascii_out[17];
      memset (ascii_out, ' ', 16);
      ascii_out[16] = '\0';
      // for each of the 4 words in the row
      for (i = 0; i < 4; i++) {
         snprintf (buf, sizeof (buf), " ");
         s2e()->getDebugStream () << buf;
         // for each of the 4 bytes in the word
         for (j = 0; j < 4; j++) {
            if (curr_addr < min_addr) {
               snprintf (buf, sizeof (buf), "  ");
               s2e()->getDebugStream () << buf;
            }
            else if (curr_addr <= end_addr) {
               if (force_print || ((timesUsed (s, (curr_addr - base) ) != 0) && validated (s, (curr_addr - base) ) ) ) { 
                  char tmp = byte (s, (curr_addr - base) );
                  snprintf (buf, sizeof (buf), "%02x", (unsigned int) tmp & 0x000000ff);
                  s2e()->getDebugStream () << buf;
                  ascii_out[(i * 4) + j] = isprint (tmp) ? tmp : '.';
               }
               else {
                  //if (timesUsed (s, (curr_addr - base) ) == 0 || !validated (s, (curr_addr - base) ) ) {
                  s2e()->getDebugStream () << "--";
                  ascii_out[(i * 4) + j] = '.';
               }
             }
             else {
                s2e()->getDebugStream () << "  ";
             }
             curr_addr++;
          } // end for each byte
       } // end for each word
       s2e()->getDebugStream () << "  " << ascii_out << '\n';
    } // end while each row
    s2e()->getDebugStream () << '\n';
    
    return;
} // end fn printSnapshot


void CodeXt::printMemMap (Mem_map m, uint64_t base) {
   s2e()->getDebugStream () << " >> Printing the memory map \"" << m.name << "\" (" << std::dec << (uint32_t) m.snaps.size () << " snapshots)\n";
   for (unsigned i = 0; i < m.snaps.size (); i++) {
      s2e()->getDebugStream () << " >>    Printing snapshot " << i << '\n';
      printSnapshot (m.snaps[i], base, false);
   }
   return;
} // end fn printMemMap


void CodeXt::appendSnapshot (Mem_map& map, unsigned len) {
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
   map.snaps.push_back (s);
   return;
} // end fn appendSnapshot
 
 
unsigned CodeXt::timesUsed (Snapshot s, uint64_t pc) {
   if (s.mem_bytes.size () <= pc) {
      return 0;
   }
   return s.mem_bytes[pc].times_used;
} // end fn timesUsed


uint8_t CodeXt::byte (Snapshot s, uint64_t pc) {
   // this also checks if pc is in range
   if (timesUsed (s, pc) <= 0) {
      return 0;
   }
   return s.mem_bytes[pc].byte;
} // end fn byte


bool CodeXt::validated (Snapshot s, uint64_t pc) {
   if (s.mem_bytes.size () <= pc) {
      return false;
   }
   return s.mem_bytes[pc].validated;
} // end fn validated


void CodeXt::timesUsedInc (Snapshot& s, uint64_t pc) {
   if (s.mem_bytes.size () <= pc) {
      return;
   }
   s.mem_bytes[pc].times_used++;
   return;
} // end fn timesUsedInc


void CodeXt::byteWrite (Snapshot& s, uint64_t pc, uint8_t value) {
   if (s.mem_bytes.size () <= pc) {
      return;
   }
   s.mem_bytes[pc].byte = value;
   return;
} // end fn byteWrite 


void CodeXt::validate (Snapshot& s, uint64_t pc) {
   if (s.mem_bytes.size () <= pc) {
      return;
   }
   s.mem_bytes[pc].validated = true;
   return;
} // end fn validated


void CodeXt::invalidate (Snapshot& s, uint64_t pc) {
   if (s.mem_bytes.size () <= pc) {
      return;
   }
   s.mem_bytes[pc].validated = false;
   return;
} // end fn invalidated




 
 




void CodeXt::fuzzFork (S2EExecutionState* state, unsigned int start, unsigned int end) {
   /** Emulate fork via WindowsApi forkRange Code */
   unsigned int i;
	s2e()->getDebugStream () << " >> fuzzFork s: " << start << " e: " << end << '\n';
   
   //assert(m_functionMonitor);
   klee::ref<klee::Expr> symb = state->createSymbolicValue (klee::Expr::Int32, "fuzz_symb");
   S2EExecutionState* curState = state;
   // by making this 1 shy of iterations you can leverage i value afterwards and the first input state so it doesn't go to waste
   for (i = start; i < end; i++) {
      //s2e()->getDebugStream () << "fuzzClone: 2 " << '\n';
      klee::ref<klee::Expr> cond = klee::NeExpr::create (symb, klee::ConstantExpr::create (i, klee::Expr::Int32) );
      //s2e()->getDebugStream () << "fuzzClone: 3 " << '\n';
      klee::Executor::StatePair sp = s2e()->getExecutor()->fork (*curState, cond, false);
      //s2e()->getDebugStream () << "fuzzClone: 4 " << '\n';
      S2EExecutionState* ts = static_cast<S2EExecutionState* >(sp.first);
      S2EExecutionState* fs = static_cast<S2EExecutionState* >(sp.second);
      fs->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(i), 4); // set the return value
      curState = ts;
   }
   
   state->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(i), 4); // set the return value
   return;
} // end fn fuzzFork


// Constraints are stored in klee::ExecutionState::constraints. It's just a vector of expressions. You can iterate through it
// try deleting old ones that this fork makes	
void CodeXt::fuzzForkSingle (S2EExecutionState* state, unsigned int value) {
   /** Emulate fork via WindowsApi forkRange Code */
	s2e()->getDebugStream () << " >> fuzzForkSingle value: " << value << '\n';
   DECLARE_PLUGINSTATE (CodeXtState, state);
   if (!plgState->has_created_symb) { // 10Jun2014 condition added by RJF
      //klee::ref<klee::Expr> symb = state->createSymbolicValue (klee::Expr::Int32, "fuzz_symb");
      plgState->symb = state->createSymbolicValue (klee::Expr::Int32, "fuzz_symb");
      plgState->has_created_symb = true;
	}
   klee::ref<klee::Expr> cond = klee::NeExpr::create (plgState->symb, klee::ConstantExpr::create (value, klee::Expr::Int32) );
   //klee::ref<klee::Expr> cond = klee::NeExpr::create (symb, klee::ConstantExpr::create (value, klee::Expr::Int32) );
   klee::Executor::StatePair sp = s2e()->getExecutor()->fork (*state, cond, false);
   S2EExecutionState* fs = static_cast<S2EExecutionState*>(sp.second);
   // set the return value for state 1 to given value
   fs->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(value), 4);	
	
   // set the return value for state 0 to a canary
	purgeFuzzForkConstraints (state);
   value = 0xffffffff;
   state->writeCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(value), 4);
   return;
} // end fn fuzzForkSingle


bool CodeXt::isaFuzzForkConstraint (klee::ref<klee::Expr> e) {
	if (((klee::Expr*) e.get())->getKind () == klee::Expr::Read && (getLabelStr (e)).find ("fuzz_symb") != std::string::npos) {
		return true;
	}
	bool ret = false;
	for (unsigned i = 0; i < ((klee::Expr*) e.get())->getNumKids (); i++) {
		if (isaFuzzForkConstraint (((klee::Expr*) e.get())->getKid (i)) ) {
			ret = true;
		}
	}
	return ret;
} // end fn isaFuzzForkConstraint


void CodeXt::purgeFuzzForkConstraints (S2EExecutionState* state) {
	// Constraints are stored in klee::ExecutionState::constraints. It's just a vector of expressions. You can iterate through it.
	// state->constraints is a klee::ConstraintManager
	// the constraints that we want to remove look like: (Eq (w32 0) (ReadLSB w32 0 v0_fuzz_symb_0))
	std::vector< klee::ref<klee::Expr> > cm_new_vector;
	klee::ConstraintManager::constraint_iterator it = state->constraints.begin ();
	klee::ConstraintManager::constraint_iterator ie = state->constraints.end ();
	for (unsigned i = 0; it != ie; ++it) {
		klee::ref<klee::Expr> it_i = *it;
		if (isaFuzzForkConstraint (*it) ) {
			s2e()->getDebugStream () << " >> found fuzzFork constraints[" << i << "]: " << it_i << '\n';
		}
		else {
			s2e()->getDebugStream () << " >> found fuzzFork other constraints[" << i << "]: " << it_i << '\n';
		}
		cm_new_vector.push_back (it_i); // note that right now it's not purging anything, everything is added back in
		i++;
	}
	/*
	// this is a custom accessor I added
	// there was no public interface in the class to remove constraints
	// it may be worth adding a cut fn, where you can fun .erase (pos, cnt)
	state->constraints.clear ();
	for (unsigned i = 0; i < cm_new_vector.size (); i++) {
		s2e()->getDebugStream () << " >> restoring constraint[" << i << "]: " << cm_new_vector[i] << '\n';
		state->constraints.addConstraint (cm_new_vector[i]);
	}*/
	/* // show modified constraints
	it = state->constraints.begin ();
	ie = state->constraints.end ();
	for (unsigned i = 0; it != ie; ++it) {
		klee::ref<klee::Expr> it_i = *it;
		s2e()->getDebugStream () << " >> constraints_new[" << i << "]: " << it_i << '\n';
		i++;
	}*/
	return;	
} // end fn purgeFuzzForkConstraints
/*
fuzzFork calls S2EExecutor::StatePair S2EExecutor::fork(ExecutionState &current, ref<Expr> condition, bool isInternal)
which calls Executor::StatePair Executor::fork(ExecutionState &current, ref<Expr> condition, bool isInternal)
which contains a call to addConstraint
                                         
inside you can skip creating the conditions maybe
the only call that may need the conditions is StatePair res = Executor::fork(current, condition, isInternal);
look into how to help it not need it.
finishes with a call to S2EExecutor::doStateFork(S2EExecutionState *originalState,
                              const vector<S2EExecutionState*>& newStates,
                              const vector<ref<Expr> >& newConditions)
inside that you remove for loop, no need for condition 
"Another source of overhead might be the constraint list. If you keep forking in a loop, its size will grow by one on each iteration, even if you always have only 2 states. It might be worth clearing it or dropping the constraints created by your fork loop."
Vitaly
"The slow down probably happens because you have too many constraints on a path. A better option would be to simply make a bunch of states without adding any constraints. This would require some tweaks to the execution engine (i.e., skip the addConstraint call)." Vitaly

RJF: TODO make a special S2EExecutor fork which calls a special kleeExecutor fork which doesn't do the addConstraint. OR purge the constaints of fuzzFork exprs
*/




CodeXtState::CodeXtState () {
   oTIE_connected = false;
   oTBE_connected = false;
   oTBS_connected = false;
   oDMA_connected = false;
	oSC_connected = false;
   debugs_connected = false;
   flush_tb_on_change = false;
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
   execed_insns = 0;
   pc_of_next_insn_from_last_IoB = 0;
   pc_of_next_insn = 0;
   expecting_jmp_OOB = false;
   syscall_cnt = 0;
   ti_seq_num = 0;
   tb_seq_num = 0;
   oTBE_nextpc = 0;
   last_fpu_pc = 0;
   has_created_symb = false;
   //has_created_fuzz_cond = false;
   x_is_symb = false;
	in_priv_mode = false;
	in_ignore_mode = false;
   read_fd = 0;
   read_dst = 0;
   read_sock = false;
   get_read_fd = false;
	//reg_write.addr = 0;
} // end fn CodeXtState


CodeXtState::CodeXtState (S2EExecutionState* s, Plugin* p) {
   oTIE_connected = false;
   oTBE_connected = false;
   oTBS_connected = false;
	oSC_connected = false;
   oDMA_connected = false;
   debugs_connected = false;
   flush_tb_on_change = false;
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
   execed_insns = 0;
   pc_of_next_insn_from_last_IoB = 0;
   pc_of_next_insn = 0;
   expecting_jmp_OOB = false;
   syscall_cnt = 0;
   ti_seq_num = 0;
   tb_seq_num = 0;
   oTBE_nextpc = 0;
   last_fpu_pc = 0;
   has_created_symb = false;
   //has_created_fuzz_cond = false;
   x_is_symb = false;
	in_priv_mode = false;
	in_ignore_mode = false;
   read_fd = 0;
   read_dst = 0;
   read_sock = false;
   get_read_fd = false;
	//reg_write.addr = 0;
} // end fn CodeXtState


CodeXtState::~CodeXtState () {
   /*if (oTIE_connected) {
      oTIE_connection.disconnect ();
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
   debugs_connected = false;*/
   // is this destroying all these vectors properly?  
   //Trans_Trace   trans_trace;
   //Exec_Trace    exec_trace;
   //Data_Trace    write_trace;
   //Syscall_Trace sysc_trace;
   //Mem_map code_map;
   //Mem_map data_map;
   
} // end fn ~CodeXtState


PluginState* CodeXtState::clone () const {
   return new CodeXtState (*this);
} // end fn clone


PluginState* CodeXtState::factory (Plugin* p, S2EExecutionState* s) {
   return new CodeXtState (s, p);
} // end fn factory





} // namespace plugins
} // namespace s2e


#endif

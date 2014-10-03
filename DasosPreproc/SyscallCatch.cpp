#ifndef S2E_PLUGINS_SYSCALLCATCH_CPP
#define S2E_PLUGINS_SYSCALLCATCH_CPP

/*extern "C" {
#include "config.h"
#include "qemu-common.h"
extern struct CPUX86State* env;
}

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Plugins/Opcodes.h>
#include <s2e/ConfigFile.h>

extern struct CPUX86State* env;
extern s2e::S2EExecutionState* state;
*/
#include "SyscallCatch.h"


namespace s2e {
namespace plugins {


S2E_DEFINE_PLUGIN (SyscallCatch, "Prints Syscall numbers and addresses", "SyscallCatch");


void SyscallCatch::initialize (S2EExecutionState* state) {
   DECLARE_PLUGINSTATE (SyscallCatchState, state);
   plgState->oExc_connection = s2e()->getCorePlugin()->onException.connect (sigc::mem_fun(*this, &SyscallCatch::onException) );
   return;
} // end fn initialize


void SyscallCatch::onException (S2EExecutionState* state, unsigned exception_idx, uint64_t pc) {
   s2e()->getDebugStream() << " >> oExc pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " exception_idx: " << std::dec << exception_idx << "(0x" << std::hex << std::noshowbase << std::setw(2) << std::setfill('0') << exception_idx << ")\n";
   //state->dumpX86State(s2e()->getDebugStream () );
   // 0x80 128d is software interrupt
   if (exception_idx == 0x80) {
      // get eax register
      uint64_t int_num = 0;
      bool ok = state->readCpuRegisterConcrete (CPU_OFFSET(regs[R_EAX]), &(int_num), 4);
      int_num = int_num & 0xffffffff;
      if (!ok) {
         s2e()->getWarningsStream (state) << "!! ERROR: symbolic argument was passed to s2e_op in SyscallCatch onException\n";
         return;
      }
      s2e()->getDebugStream() << " >> oExc INT 0x80 pc: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " syscall_num: " << std::dec << int_num << "(0x" << std::hex << std::noshowbase << std::setw(2) << std::setfill('0') << int_num << ")\n";
      //state->dumpX86State(s2e()->getDebugStream () );
      // onExc happens before oEI, so call oEI manually if oSysc is end point
      //onExecuteInsn (state, pc);
      onSyscall (state, pc, int_num);
   }
   return;
} // end fn onException


void SyscallCatch::onSyscall (S2EExecutionState* state, uint64_t pc, uint32_t sysc_number) {
   // the kernel doesn't make system calls, so getPid () is accurate here
   uint64_t pid = state->getPid();
   s2e()->getDebugStream() << "Syscall " << std::hex << sysc_number << " at addr 0x" << std::noshowbase << std::setw(8) << std::setfill('0') << pc << " from pid: " << std::dec << pid << "\n";
   return;
} // end fn onSyscall


// grab an X86 context
void SyscallCatch::dumpX86State (S2EExecutionState* state, struct X86State& s) {
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

   
void SyscallCatch::printX86State (struct X86State s) {
   s2e()->getDebugStream () << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << " eax:0x" << s.eax << " ebx:0x" << s.ebx << " ecx:0x" << s.ecx << " edx:0x" << s.edx << " esi:0x" << s.esi << " edi:0x" << s.edi << " ebp:0x" << s.ebp << " esp:0x" << s.esp << " eip:0x" << s.eip << " cr2:0x" << s.cr2 << std::dec << "\n";
   return;
} // end fn printX86State


} // namespace plugins
} // namespace s2e


#endif

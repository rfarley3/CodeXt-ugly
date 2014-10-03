#ifndef S2E_PLUGINS_SYSCALLCATCH_H
#define S2E_PLUGINS_SYSCALLCATCH_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>


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
struct Syscall {
   uint64_t seq_num;   // execution sequence number of the int 0x80
   uint64_t addr;      // the address of the system call 
   uint8_t  num;       // system call number (eax)
   struct X86State preState;  // state->dumpX86State
   struct X86State postState; // state->dumpX86State
   
};
typedef std::vector<Syscall>  Syscall_Trace;

namespace s2e {
namespace plugins {
class SyscallCatch : public Plugin { 
	   S2E_PLUGIN

	private:

	public:
		SyscallCatch (S2E* s2e): Plugin (s2e) {}
		~SyscallCatch () {}

   void initialize    ();
   void onException   (S2EExecutionState* state, unsigned exception_idx, uint64_t pc);
   void onSyscall     (S2EExecutionState* state, uint64_t pc, uint32_t sysc_number);
   void dumpX86State  (S2EExecutionState* state, struct X86State& s);
   void printX86State (struct X86State s);
};


class SyscallCatchState: public PluginState {
	private:
   	sigc::connection oExc_connection;     // onException
		
	public:
   	SyscallCatchState ();
   	SyscallCatchState (S2EExecutionState* s, Plugin* p);
   	virtual ~SyscallCatchState ();
   	virtual PluginState* clone () const;
   	static PluginState* factory (Plugin* p, S2EExecutionState* s);
   
   friend class SyscallCatch;
};

} // namespace plugins
} // namespace s2e


#endif

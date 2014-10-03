-- RJF
-- config file for S2E (using lua)
-- 11 Feb 2014 allows you to specify marking certain bytes as symbolic, which byte to monitor for taint, tuning for early termination, multipath bool, multisysc bool


s2e = {
    kleeArgs = {
      "--use-dfs-search=true",
      "--state-shared-memory=true",
    }
}


plugins = {
   "BaseInstructions",           -- Enable custom opcodes
   "HostFiles",                  -- allows easier file transfer access
   "DasosPreproc",
}

    
pluginsConfig = {}
    

pluginsConfig.HostFiles = {
   baseDir = "/mnt/RJFDasos/HostFiles"
}

pluginsConfig.DasosPreproc = {
	-- you can specify symbolic variables with: symbVars = { "Name", "Address (offset from start of shellcode)", "Length in bytes", "Trigger (num of insns to execute before marking as symbolic)" }. For example, mark the 1B key which is at address 20 after the 2nd insn: symbVars = { "Key", "20", "1", "2" }. for another example, the same as the previous but also mark another 4B blob at address 40 after the 1st insn: symbVars = { "Key", "20", "1", "2", "Blob", "40", "4", "1" }
	-- Using the same format you can specify memory addresses that you want to check (after each executed insn) if they turn symbolic using monitorVars. For example monitor an output word at address 60 after the 10th insn: monitorVars = { "Out", "60", "4", "10" }
	-- If the name starts with a _, then it is a special location, such as _ESP is the esp register. For now, these will have offsets of 0 and lengths of 4.
	-- The naming convention is to use data_ for data taints and code_ for code taints.


   -- test taint propogation on data only
   -- avalanche addition (mark x as symb, do z = x + y, test if z becomes marked as symb)
   -- use with ./shellcode-wrapper -i avalanche-addition.rawshell -x -f 0 -c 1
	--symbVars = { "data_x", "33", "1", "1" },
	--monitorVars = { "z", "35", "1", "1", "y", "34", "1", "1" },
	
   -- test taint propogation on buffer overflow
	-- symb buf is used to overflow a local var, making retaddr symbolic
   -- use with ./shellcode-wrapper -i BasicTaint.rawshell -x -f 0 -c 1 
	-- or with ./shellcode-wrapper -i BasicTaintCntDown.rawshell -x -f 0 -c 1 
	--symbVars = { "data_buf", "20", "8", "7" },
	--monitorVars = { "_ESP", "0", "4", "7"},
	-- with ./shellcode-wrapper -i BoundedTaint.rawshell -x -f 0 -c 1 
	--symbVars = { "data_b1", "26", "2", "7", "data_b2", "24", "2", "7" },
	--monitorVars = { "_ESP", "0", "4", "7"},
	
   -- test executing a symbolic byte
	-- avalance XOR (mark key as symb, track 1st decoded byte location, see if executes any decoded bytes)
   -- use with ./shellcode-wrapper -i hw-xor.rawshell -x -f 0 -c 1
	symbVars = { "code_Key", "13", "1", "1" },
	monitorVars = { "Out", "49", "1", "1" },


	-- The following allow you to tune the decisions used to determine if a string of executed bytes forms something you are interested in	
	maxInRangeInsn  = 100000, -- max cummulative insns to execute within bounds of the shellcode before terminating early, defaults to 100000
	maxOutRangeInsn =  10000, -- max cummulative insns to execute out of bounds of the shellcode (having had exec >= 1 within bounds insn) before terminating early, defaults to 10000
	maxKernelInsn   =  10000, -- max contiguous kernelspace insns to execute (reset if returns within bounds of the shellcode, or execs a non-kernel OoB insn) before terminating early, defaults to 10000. If TLB is flushed (CR3 overwritten), then cap not enforced. Has to have exec >= 1 within bounds insn.
	maxKillableInsn =  10000, -- max contiguous killable insns to execute (OoB | Kernel) before terminating early, defaults to 10000. This covers the case when a emulation bounces between kernel and OoB, and allows kernelspace to count as cummulative with the OoB limit.
	
	clusterWritesBy = 10, -- if more than x insns occur since last write cluster, then make new cluster for deltas on the memory maps, defaults to 10
	minExecInsns    =  6, -- min executed insns needed for a fragment to be considered legit code
	minExecBytes    = 15, -- min bytes executed (sum of all bytes from each exec'ed insn) needed for a fragment to be considered legit code
	
	multiPath = false,   -- fork or not, for multipath exploration
	multiSysc = false,   -- should execution continue past the first system call
	
	-- TODO
	-- which system call numbers count as end of execution
	-- perhaps even what system call number and offset to be looking for (in case doesnt exist in wrapper input)
	-- complex or runtime-only memory locations, such as symbVars = { "conditional", "EBP-0xd", "1", "10" }
}

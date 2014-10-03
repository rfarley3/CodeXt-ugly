-- 26 July RJF
-- config file for S2E (using lua)


s2e = {
    kleeArgs = {
      --"--use-random-path",
      --"--use-cex-cache=true",
      --"--use-cache=true",
      --"--use-fast-cex-solver=true",
      --"--max-stp-time=10",
      --"--use-expr-simplifier=true",
      --"--print-expr-simplifier=false",
      --"--flush-tbs-on-state-switch=false",
      --"--use-batching-search=true", -- round robin the states
      --"--batch-time=5.0", -- time for each state to run before switching
      "--use-dfs-search=true",
      "--state-shared-memory=true",
      "--max-memory-inhibit=true",
      "--max-memory=200",
    }
}


plugins = {
   "BaseInstructions",              -- Enable custom opcodes
   --"RawMonitor",                  -- Enable declaring segments of memory as modules for monitoring
   --"ModuleExecutionDetector",

   --"SymbolicHardware",
   --"EdgeKiller",
   --"Annotation",

   --"ExecutionTracer",               -- Base plugin upon which all tracers depend. This plugin records fork points so that offline analysis tools can reconstruct the execution tree. This plugin is useful by itself to obtain a fork profile of the system and answer questions such as: Which branch forks the most? What is causing path explosion?
   --"ModuleTracer",
   --"TranslationBlockTracer",
   --"TestCaseGenerator",             --Outputs a test case whenever a path terminates. The test case consists of concrete input values that would exercise the given path.

   --"FunctionMonitor",
   --"StateManager",
    
    
   "HostFiles",                     -- allows easier file transfer access

   --"InstructionTracker",         -- Tutorial custom plugin
   "InterruptMonitor",
   "LinuxSyscallMonitor",
   "DasosPreproc",
}

    
pluginsConfig = {}
    
--pluginsConfig.InstructionTracker = {
   -- The address we want to track
--   addressToTrack=0x12345
--}
    

pluginsConfig.HostFiles = {
   baseDir = "/mnt/RJFDasos/HostFiles"
}

-- has a corresponding line in the source: void s2e_rawmon_loadmodule (const char *name, unsigned loadbase, unsigned size);
-- in this case: s2e_rawmon_loadmodule ("shellcode", shell, shell_len);
--pluginsConfig.RawMonitor = {
--    kernelStart = 0xc0000000,          -- always the case
--    myprog_id = {
--        name = "shellcode",            -- Set to the name given in the source by the custom instruction
--        start = 0x0,                   -- Set to zero if the runtime address is determined by the custom instruction
--        --size = --put your size here, e.g., 52505, -- The size of the module binary.
--        --nativebase = 0x8048000,        -- The default base address of the binary set by the linker
--        delay = true,                  -- Set to true when the s2e_rawmon_loadmodule custom instruction is used
--        kernelmode = false             -- Whether the module lies above or below the kernel-mode threshold
--    }
--}

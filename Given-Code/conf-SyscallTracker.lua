-- 26 July RJF
-- config file for S2E (using lua)


s2e = {
    kleeArgs = {
        "--use-batching-search",
        "--use-random-path",
        "--use-cex-cache=true",
        "--use-cache=true",
        "--use-fast-cex-solver=true",
        "--max-stp-time=10",
        "--use-expr-simplifier=true",
        "--print-expr-simplifier=false",
        "--flush-tbs-on-state-switch=false",
    }
}


plugins = {
    "BaseInstructions",           -- Enable custom opcodes
    --"ModuleExecutionDetector",

    --"SymbolicHardware",
    --"EdgeKiller",
    --"Annotation",

    "ExecutionTracer",            -- Basic tracing, required for test case generation
    --"ModuleTracer",
    --"TranslationBlockTracer",

    --"FunctionMonitor",
    --"StateManager",
    
    
    "HostFiles",                     -- allows easier file transfer access

    --"InstructionTracker",         -- This custom plugin
    "InterruptMonitor",
    "LinuxSyscallMonitor",
    "SyscallTracker",
}

    
pluginsConfig = {}
    
--pluginsConfig.InstructionTracker = {
   -- The address we want to track
--   addressToTrack=0x12345
--}
    

pluginsConfig.HostFiles = {
   baseDir = "/mnt/RJFDasos/DasosPreproc/HostFiles"
   --baseDirs = {"/home/s2e/s2e/dasos/SyscallTracker/HostFiles", "/mnt/RJFDasos/SyscallTracker/HostFiles"}
}


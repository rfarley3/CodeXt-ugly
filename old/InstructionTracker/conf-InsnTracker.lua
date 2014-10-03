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

    "InstructionTracker",         -- This custom plugin
}

    
pluginsConfig = {}
    
pluginsConfig.InstructionTracker = {
   -- The address we want to track
   addressToTrack=0x12345
}
    


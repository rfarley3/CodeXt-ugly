-- File: tutorial1.lua
s2e = {
  kleeArgs = {
    -- Run each state for at least 1 second before
    -- switching to the other:
    "--use-batching-search=true", "--batch-time=1.0"
  }
}
plugins = {
  -- Enable a plugin that handles S2E custom opcode
  "BaseInstructions",
  "HostFiles",                      -- allows easier file transfer access, ENABLE if our VM, disable for purer test on Vitaly's VM
  "ExecutionTracer",                -- req for TestCaseGenerator
  "TestCaseGenerator"               -- enable test case generation, not sure what this does, or how that is different than symb executino
   --"InterruptMonitor",
   --"LinuxSyscallMonitor",
   --"DasosPreproc",
}


pluginsConfig = {}

pluginsConfig.HostFiles = {
   baseDir = "/mnt/RJFDasos/HostFiles"
}

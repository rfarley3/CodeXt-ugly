-- 4 June 2013 RJF
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

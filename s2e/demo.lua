s2e = {
  kleeArgs = {
     "--use-batching-search=true", "--batch-time=2.0"
  }
}
plugins = {
  -- Enable S2E custom opcodes
  "BaseInstructions",

  -- Basic tracing, required for test case generation
  "ExecutionTracer",

  -- Enable the test case generator plugin
  "TestCaseGenerator"
}


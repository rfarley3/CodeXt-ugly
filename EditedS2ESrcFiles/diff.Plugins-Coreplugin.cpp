--- /home/s2e/s2e/s2e/qemu/s2e/Plugins/CorePlugin.cpp	2012-04-16 02:27:52.769226001 -0700
+++ EditedS2ESrcFiles/Plugins-Coreplugin.cpp	2014-05-19 14:10:18.000000000 -0700
@@ -254,6 +254,29 @@
     }
 }
 
+
+void s2e_on_translate_instruction_end_RJF (S2E* s2e, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc, unsigned use_nextpc, uint64_t nextpc)
+{
+   //s2e_on_translate_instruction_end (s2e, state, tb, pc, use_nextpc ? nextpc : (uint64_t)-1);
+   assert(state->isActive());
+   
+   ExecutionSignal *signal = static_cast<ExecutionSignal*>(tb->s2e_tb->executionSignals.back());
+   assert(signal->empty());
+   
+   try {
+      s2e->getCorePlugin()->onTranslateInstructionEnd_RJF.emit(signal, state, tb, pc, nextpc); //RJF
+      s2e->getCorePlugin()->onTranslateInstructionEnd.emit(signal, state, tb, pc);
+      if(!signal->empty()) {
+         s2e_tcg_instrument_code(s2e, signal, pc, use_nextpc ? nextpc : (uint64_t)-1);
+         tb->s2e_tb->executionSignals.push_back(new ExecutionSignal);
+      }
+   } catch(s2e::CpuExitException&) {
+      s2e_longjmp(env->jmp_env, 1);
+   }
+   return;
+} // end fn s2e_on_translate_instruction_end_RJF
+
+
 //Nextpc is the program counter of the of the instruction that
 //follows the one at pc, only if it does not change the control flow.
 void s2e_on_translate_instruction_end(
@@ -267,6 +290,7 @@
     assert(signal->empty());
 
     try {
+        s2e->getCorePlugin()->onTranslateInstructionEnd_RJF.emit(signal, state, tb, pc, nextpc); //RJF
         s2e->getCorePlugin()->onTranslateInstructionEnd.emit(signal, state, tb, pc);
         if(!signal->empty()) {
             s2e_tcg_instrument_code(s2e, signal, pc, nextpc);
@@ -460,3 +484,27 @@
         assert(false && "Cannot throw exceptions here. VM state may be inconsistent at this point.");
     }
 }
+
+/*// RJF for the folowing function
+// this is closest to the existing fn for reporting when memory is updated
+void s2e_on_silent_concretize_old (uint64_t addr, uint8_t concrete_val, const char* reason) {
+    //g_s2e->getDebugStream() << "s2e_on_silent_concretize_old\n";
+    try {
+        g_s2e->getCorePlugin()->onSilentConcretize.emit(g_s2e_state, addr, concrete_val, reason);
+    } catch(s2e::CpuExitException&) {
+        s2e_longjmp(env->jmp_env, 1);
+    }
+} // end fn s2e_on_silent_concretize*/
+
+// RJF for the folowing function
+// this is closest to the existing fn for reporting when memory is updated
+//void s2e_on_silent_concretize_new (uint64_t addr, klee::ref<klee::Expr> concretized_expr, uint8_t concrete_val, const char* reason) {
+void s2e_on_silent_concretize (uint64_t addr, void* pre_concrete_expr_ptr, uint8_t post_concrete_val, const char* reason) {
+   klee::ref<klee::Expr> pre_concrete_expr ((klee::Expr*) pre_concrete_expr_ptr);
+   //g_s2e->getDebugStream() << "s2e_on_silent_concretize\n";
+   try {
+      g_s2e->getCorePlugin()->onSilentConcretize.emit(g_s2e_state, addr, pre_concrete_expr, post_concrete_val, reason);
+   } catch(s2e::CpuExitException&) {
+      s2e_longjmp(env->jmp_env, 1);
+   }
+} // end fn s2e_on_silent_concretize
\ No newline at end of file

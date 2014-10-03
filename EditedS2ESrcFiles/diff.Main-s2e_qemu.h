--- /home/s2e/s2e/s2e/qemu/s2e/s2e_qemu.h	2012-04-16 02:27:53.159226003 -0700
+++ EditedS2ESrcFiles/Main-s2e_qemu.h	2014-05-19 14:12:58.000000000 -0700
@@ -126,11 +126,17 @@
         struct S2EExecutionState* state,
         struct TranslationBlock* tb, uint64_t pc);
 
+/** Called by cpu_gen_code() after translation of each instruction, extended */
+void s2e_on_translate_instruction_end_RJF (
+   struct S2E* s2e,
+   struct S2EExecutionState* state,
+   struct TranslationBlock* tb, uint64_t pc, unsigned use_nextpc, uint64_t nextpc);
+
 /** Called by cpu_gen_code() after translation of each instruction */
 void s2e_on_translate_instruction_end(
-        struct S2E* s2e,
-        struct S2EExecutionState* state,
-        struct TranslationBlock* tb, uint64_t pc, uint64_t nextpc);
+   struct S2E* s2e,
+   struct S2EExecutionState* state,
+   struct TranslationBlock* tb, uint64_t pc, uint64_t nextpc);
 
 /** Called by cpu_gen_code() before translation of each jump instruction */
 void s2e_on_translate_jump_start(
@@ -334,6 +340,11 @@
 //Used by S2E.h to reinitialize timers in the forked process
 int init_timer_alarm(void);
 
+//void s2e_on_silent_concretize_old (uint64_t addr, uint8_t concrete_val, const char* reason); // RJF
+// void* pre_concrete_expr, allows us to pass a klee::ref<klee:expr> through a c-wrapper // RJF
+void s2e_on_silent_concretize (uint64_t addr, void* pre_concrete_expr, uint8_t post_concrete_val, const char* reason); // RJF
+
+
 /******************************************************/
 /* Prototypes for special functions used in LLVM code */
 /* NOTE: this functions should never be defined. They */

--- /home/s2e/s2e/s2e/qemu/s2e/Plugins/CorePlugin.h	2012-04-16 02:27:52.769226001 -0700
+++ EditedS2ESrcFiles/Plugins-Coreplugin.h	2014-05-19 14:18:34.000000000 -0700
@@ -130,6 +130,14 @@
             bool /* static target is valid */,
             uint64_t /* static target pc */>
             onTranslateBlockEnd;
+            
+   /** Signal that is emitted upon end of instruction, extended by RJF */
+   sigc::signal<void, ExecutionSignal*,
+            S2EExecutionState*,
+            TranslationBlock*,
+            uint64_t /* instruction pc */,
+            uint64_t /* nextpc, adjacent subsequent insn, ignores jmps, use for length */>
+            onTranslateInstructionEnd_RJF;
 
     
     /** Signal that is emitted on code generation for each instruction */
@@ -258,6 +266,26 @@
     sigc::signal<void,
                  S2EExecutionState* /* current state */>
           onInitializationComplete;
+					  
+
+
+    /** Signal that is emitted if any klee::expr is silently concretized (klee::Executor::toConstant via S2EExecuctionStation:readRamConcrete) */
+    //sigc::signal<void, S2EExecutionState*,
+    //             uint64_t /* addr */,
+    //             uint8_t /* concrete_val */,
+    //             const char* /* reason */>
+    //      onSilentConcretize_old; // RJF
+					  
+
+	 // RJF
+	 /** Signal that is emitted if any klee::expr is silently concretized (klee::Executor::toConstant via S2EExecuctionStation:readRamConcrete) */
+	 sigc::signal<void, 
+	          S2EExecutionState*    /* current state */,
+             uint64_t              /* addr of the byte concretized */,
+				 klee::ref<klee::Expr> /* pre_concrete_expr */, // CorePlugin.cpp converts the c void* concretized_expr_ptr into this cpp ref
+             uint8_t               /* post_concrete_val */,
+             const char*           /* reason */>
+	      onSilentConcretize;
 };
 
 } // namespace s2e

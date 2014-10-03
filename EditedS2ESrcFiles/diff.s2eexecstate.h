--- /home/s2e/s2e/s2e/qemu/s2e/S2EExecutionState.h	2012-04-16 02:27:53.159226003 -0700
+++ EditedS2ESrcFiles/s2e-S2EExecutionState.h	2014-03-24 18:10:53.000000000 -0700
@@ -218,6 +218,7 @@
 
     /** Write CPU general purpose register */
     void writeCpuRegister(unsigned offset, klee::ref<klee::Expr> value);
+    void writeCpuRegisterRaw(unsigned offset, klee::ref<klee::Expr> value);
 
     /** Read concrete value from general purpose CPU register */
     bool readCpuRegisterConcrete(unsigned offset, void* buf, unsigned size);

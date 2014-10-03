--- /home/s2e/s2e/s2e/qemu/s2e/Plugins/ExecutionTracers/TraceEntries.h	2012-04-16 02:27:52.769226001 -0700
+++ EditedS2ESrcFiles/ExecutionTracers-TraceEntries.h	2012-09-25 16:15:05.000000000 -0700
@@ -332,6 +332,7 @@
         TB_JMP, TB_JMP_IND,
         TB_COND_JMP, TB_COND_JMP_IND,
         TB_CALL, TB_CALL_IND, TB_REP, TB_RET
+        , TB_SYSENTER, TB_SYSEXIT, TB_INTERRUPT // RJF
     };
 
     enum EX86Registers

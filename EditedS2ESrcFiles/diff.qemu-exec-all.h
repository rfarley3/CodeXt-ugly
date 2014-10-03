--- /home/s2e/s2e/s2e/qemu/exec-all.h	2011-01-24 01:15:11.829830005 -0800
+++ EditedS2ESrcFiles/qemu-exec-all.h	2013-03-04 17:47:00.000000000 -0800
@@ -158,12 +158,14 @@
     TB_JMP, TB_JMP_IND,
     TB_COND_JMP, TB_COND_JMP_IND,
     TB_CALL, TB_CALL_IND, TB_REP, TB_RET
+    , TB_SYSENTER, TB_SYSEXIT, TB_INTERRUPT // RJF
 };
 
 #ifdef CONFIG_S2E
 enum JumpType
 {
     JT_RET, JT_LRET
+    , JT_IRET            // RJF
 };
 #endif
 
@@ -218,6 +220,8 @@
     struct S2ETranslationBlock* s2e_tb;
     struct TranslationBlock* s2e_tb_next[2];
     uint64_t pcOfLastInstr; /* XXX: hack for call instructions */
+    uint8_t lenOfLastInstr; /* RJF, allows translate.c to report back instruction length */
+    uint64_t pcOfNextInstr; /* RJF, allows translate.c to report the next PC it plans to execute */
 #endif
 };
 

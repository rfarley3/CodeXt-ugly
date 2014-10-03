--- /home/s2e/s2e/s2e/qemu/target-i386/translate.c	2012-04-16 02:27:53.159226003 -0700
+++ EditedS2ESrcFiles/i386-translate.c	2014-03-25 07:35:43.000000000 -0700
@@ -157,6 +157,7 @@
 #else
 #define SET_TB_TYPE(t)
 #define s2e_on_translate_jump_start(...)
+#define s2e_on_syscall(...)    // RJF
 #endif
 
 #ifdef CONFIG_S2E
@@ -181,7 +182,7 @@
 
 #endif
 
-static void gen_eob(DisasContext *s);
+static void gen_eob(DisasContext *s, target_ulong nextPc);
 static void gen_jmp(DisasContext *s, target_ulong eip);
 static void gen_jmp_tb(DisasContext *s, target_ulong eip, int tb_num);
 
@@ -336,16 +337,32 @@
 #endif
 
 #ifdef CONFIG_S2E
-static inline void gen_instr_end(DisasContext *s)
+static inline void gen_instr_end(DisasContext *s, target_ulong nextPc) // RJF
 {
     if (!s->done_instr_end) {
-        s2e_on_translate_instruction_end(g_s2e, g_s2e_state, s->tb, s->insPc, s->useNextPc ? s->nextPc : (uint64_t)-1);
+        // RJF s->insPc is the tb's pc, the last arg is nextpc
+        // RJF but s->nextPC is not set if jmps...
+        s->tb->pcOfNextInstr = nextPc; //s->useNextPc ? s->nextPc : s->tb->pcOfNextInstr; //(uint64_t)-1; // RJF
+        //RJF s2e_on_translate_instruction_end(g_s2e, g_s2e_state, s->tb, s->insPc, s->useNextPc ? s->nextPc : (uint64_t)-1);
+        s2e_on_translate_instruction_end_RJF (g_s2e, g_s2e_state, s->tb, s->insPc, s->useNextPc, s->nextPc);
         s->done_instr_end = 1;
     }
 }
 
 #endif
 
+
+
+
+// RJF the following function allows us to keep track of the length of the intruction disassembled
+void incLenOfLastInstr (TranslationBlock* tb, int change) {
+   #ifdef CONFIG_S2E
+   tb->lenOfLastInstr += change;
+   #endif
+   return;
+} // end fn incLenOfLastInstr RJF
+
+
 static inline void gen_op_mov_reg_v(int ot, int reg, TCGv t0)
 {
     TCGv tmp;
@@ -651,35 +668,35 @@
 
 static inline void gen_op_st_v(int idx, TCGv t0, TCGv a0)
 {
-    int mem_index = (idx >> 2) - 1;
-    switch(idx & 3) {
-    case 0:
-        tcg_gen_qemu_st8(t0, a0, mem_index);
-        break;
-    case 1:
-        tcg_gen_qemu_st16(t0, a0, mem_index);
-        break;
-    case 2:
-        tcg_gen_qemu_st32(t0, a0, mem_index);
-        break;
-    default:
-    case 3:
-        /* Should never happen on 32-bit targets.  */
-#ifdef TARGET_X86_64
-        tcg_gen_qemu_st64(t0, a0, mem_index);
-#endif
-        break;
-    }
+   int mem_index = (idx >> 2) - 1;
+   switch(idx & 3) {
+      case 0:
+         tcg_gen_qemu_st8(t0, a0, mem_index);
+         break;
+      case 1:
+         tcg_gen_qemu_st16(t0, a0, mem_index);
+         break;
+      case 2:
+         tcg_gen_qemu_st32(t0, a0, mem_index);
+         break;
+      default:
+      case 3:
+         /* Should never happen on 32-bit targets.  */
+         #ifdef TARGET_X86_64
+         tcg_gen_qemu_st64(t0, a0, mem_index);
+         #endif
+         break;
+   }
 }
 
 static inline void gen_op_st_T0_A0(int idx)
 {
-    gen_op_st_v(idx, cpu_T[0], cpu_A0);
+   gen_op_st_v(idx, cpu_T[0], cpu_A0);
 }
 
 static inline void gen_op_st_T1_A0(int idx)
 {
-    gen_op_st_v(idx, cpu_T[1], cpu_A0);
+   gen_op_st_v(idx, cpu_T[1], cpu_A0);
 }
 
 static inline void gen_jmp_im(DisasContext *s, target_ulong pc)
@@ -1415,7 +1432,7 @@
         if (d != OR_TMP0)
             gen_op_mov_reg_T0(ot, d);
         else
-            gen_op_st_T0_A0(ot + s1->mem_index);
+           gen_op_st_T0_A0(ot + s1->mem_index);
         tcg_gen_mov_tl(cpu_cc_src, cpu_T[1]);
         tcg_gen_mov_tl(cpu_cc_dst, cpu_T[0]);
         tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_tmp4);
@@ -1432,7 +1449,7 @@
         if (d != OR_TMP0)
             gen_op_mov_reg_T0(ot, d);
         else
-            gen_op_st_T0_A0(ot + s1->mem_index);
+           gen_op_st_T0_A0(ot + s1->mem_index);
         tcg_gen_mov_tl(cpu_cc_src, cpu_T[1]);
         tcg_gen_mov_tl(cpu_cc_dst, cpu_T[0]);
         tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_tmp4);
@@ -1445,7 +1462,7 @@
         if (d != OR_TMP0)
             gen_op_mov_reg_T0(ot, d);
         else
-            gen_op_st_T0_A0(ot + s1->mem_index);
+           gen_op_st_T0_A0(ot + s1->mem_index);
         gen_op_update2_cc();
         s1->cc_op = CC_OP_ADDB + ot;
         break;
@@ -1454,7 +1471,7 @@
         if (d != OR_TMP0)
             gen_op_mov_reg_T0(ot, d);
         else
-            gen_op_st_T0_A0(ot + s1->mem_index);
+           gen_op_st_T0_A0(ot + s1->mem_index);
         gen_op_update2_cc();
         s1->cc_op = CC_OP_SUBB + ot;
         break;
@@ -1464,7 +1481,7 @@
         if (d != OR_TMP0)
             gen_op_mov_reg_T0(ot, d);
         else
-            gen_op_st_T0_A0(ot + s1->mem_index);
+           gen_op_st_T0_A0(ot + s1->mem_index);
         gen_op_update1_cc();
         s1->cc_op = CC_OP_LOGICB + ot;
         break;
@@ -2085,6 +2102,7 @@
         if (base == 4) {
             havesib = 1;
             code = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             scale = (code >> 6) & 3;
             index = ((code >> 3) & 7) | REX_X(s);
             base = (code & 7);
@@ -2097,6 +2115,7 @@
                 base = -1;
                 disp = (int32_t)ldl_code(s->pc);
                 s->pc += 4;
+                incLenOfLastInstr (s->tb, 4); // RJF
                 if (CODE64(s) && !havesib) {
                     disp += s->pc + s->rip_offset;
                 }
@@ -2105,12 +2124,14 @@
             }
             break;
         case 1:
-            disp = (int8_t)ldub_code(s->pc++);
+           disp = (int8_t)ldub_code(s->pc++);
+           incLenOfLastInstr (s->tb, 1); // RJF
             break;
         default:
         case 2:
             disp = ldl_code(s->pc);
             s->pc += 4;
+            incLenOfLastInstr (s->tb, 4); // RJF
             break;
         }
 
@@ -2174,6 +2195,7 @@
             if (rm == 6) {
                 disp = lduw_code(s->pc);
                 s->pc += 2;
+                incLenOfLastInstr (s->tb, 2); // RJF
                 gen_op_movl_A0_im(disp);
                 rm = 0; /* avoid SS override */
                 goto no_rm;
@@ -2182,12 +2204,14 @@
             }
             break;
         case 1:
-            disp = (int8_t)ldub_code(s->pc++);
+           disp = (int8_t)ldub_code(s->pc++);
+           incLenOfLastInstr (s->tb, 1); // RJF
             break;
         default:
         case 2:
             disp = lduw_code(s->pc);
             s->pc += 2;
+            incLenOfLastInstr (s->tb, 2); // RJF
             break;
         }
         switch(rm) {
@@ -2256,37 +2280,44 @@
         base = rm;
 
         if (base == 4) {
-            code = ldub_code(s->pc++);
+           code = ldub_code(s->pc++);
+           incLenOfLastInstr (s->tb, 1); // RJF
             base = (code & 7);
         }
 
         switch (mod) {
         case 0:
             if (base == 5) {
-                s->pc += 4;
+               s->pc += 4;
+               incLenOfLastInstr (s->tb, 4); // RJF
             }
             break;
         case 1:
-            s->pc++;
+           s->pc++;
+           incLenOfLastInstr (s->tb, 1); // RJF
             break;
         default:
         case 2:
-            s->pc += 4;
+           s->pc += 4;
+           incLenOfLastInstr (s->tb, 4); // RJF
             break;
         }
     } else {
         switch (mod) {
         case 0:
             if (rm == 6) {
-                s->pc += 2;
+               s->pc += 2;
+               incLenOfLastInstr (s->tb, 2); // RJF
             }
             break;
         case 1:
-            s->pc++;
+           s->pc++;
+           incLenOfLastInstr (s->tb, 1); // RJF
             break;
         default:
         case 2:
-            s->pc += 2;
+           s->pc += 2;
+           incLenOfLastInstr (s->tb, 2); // RJF
             break;
         }
     }
@@ -2356,15 +2387,18 @@
     case OT_BYTE:
         ret = ldub_code(s->pc);
         s->pc++;
+        incLenOfLastInstr (s->tb, 1); // RJF
         break;
     case OT_WORD:
         ret = lduw_code(s->pc);
         s->pc += 2;
+        incLenOfLastInstr (s->tb, 2); // RJF
         break;
     default:
     case OT_LONG:
         ret = ldl_code(s->pc);
         s->pc += 4;
+        incLenOfLastInstr (s->tb, 4); // RJF
         break;
     }
     return ret;
@@ -2393,7 +2427,7 @@
         //s->enable_jmp_im = 0;
         gen_jmp_im(s, eip);
 
-        gen_instr_end(s);
+        gen_instr_end(s, eip); //RJF
 
         tcg_gen_goto_tb(tb_num);
 
@@ -2407,7 +2441,7 @@
     } else {
         /* jump to another page: currently not optimized */
         gen_jmp_im(s, eip);
-        gen_eob(s);
+        gen_eob(s, eip); // RJF
     }
 }
 
@@ -2442,7 +2476,7 @@
         gen_set_label(l1);
         gen_jmp_im(s, val);
         gen_set_label(l2);
-        gen_eob(s);
+        gen_eob(s, next_eip); // RJF
     }
 }
 
@@ -2806,11 +2840,11 @@
 
 /* generate a generic end of block. Trace exception is also generated
    if needed */
-static void gen_eob(DisasContext *s)
+static void gen_eob(DisasContext *s, target_ulong nextPc)
 {
 
 #ifdef CONFIG_S2E
-    gen_instr_end(s);
+    gen_instr_end(s, nextPc); // RJF
 #endif
 
     if (s->cc_op != CC_OP_DYNAMIC)
@@ -2844,7 +2878,7 @@
         s->is_jmp = 3;
     } else {
         gen_jmp_im(s, eip);
-        gen_eob(s);
+        gen_eob(s, eip); // RJF
     }
 }
 
@@ -3259,7 +3293,8 @@
         gen_helper_enter_mmx();
     }
 
-    modrm = ldub_code(s->pc++);
+modrm = ldub_code(s->pc++);
+incLenOfLastInstr (s->tb, 1); // RJF
     reg = ((modrm >> 3) & 7);
     if (is_xmm)
         reg |= rex_r;
@@ -3459,7 +3494,9 @@
                 if (b1 == 1 && reg != 0)
                     goto illegal_op;
                 field_length = ldub_code(s->pc++) & 0x3F;
+                incLenOfLastInstr (s->tb, 1); // RJF
                 bit_index = ldub_code(s->pc++) & 0x3F;
+                incLenOfLastInstr (s->tb, 1); // RJF
                 tcg_gen_addi_ptr(cpu_ptr0, cpu_env,
                     offsetof(CPUX86State,xmm_regs[reg]));
                 if (b1 == 1)
@@ -3579,7 +3616,8 @@
         case 0x171: /* shift xmm, im */
         case 0x172:
         case 0x173:
-            val = ldub_code(s->pc++);
+           val = ldub_code(s->pc++);
+           incLenOfLastInstr (s->tb, 1); // RJF
             if (is_xmm) {
                 gen_op_movl_T0_im(val);
                 tcg_gen_st32_tl(cpu_T[0], cpu_env, offsetof(CPUX86State,xmm_t0.XMM_L(0)));
@@ -3726,6 +3764,7 @@
             s->rip_offset = 1;
             gen_ldst_modrm(s, modrm, OT_WORD, OR_TMP0, 0);
             val = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             if (b1) {
                 val &= 7;
                 tcg_gen_st16_tl(cpu_T[0], cpu_env,
@@ -3742,6 +3781,7 @@
                 goto illegal_op;
             ot = (s->dflag == 2) ? OT_QUAD : OT_LONG;
             val = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             if (b1) {
                 val &= 7;
                 rm = (modrm & 7) | REX_B(s);
@@ -3803,6 +3843,7 @@
         case 0x038:
             b = modrm;
             modrm = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             rm = modrm & 7;
             reg = ((modrm >> 3) & 7) | rex_r;
             mod = (modrm >> 6) & 3;
@@ -3872,6 +3913,7 @@
         crc32:
             b = modrm;
             modrm = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             reg = ((modrm >> 3) & 7) | rex_r;
 
             if (b != 0xf0 && b != 0xf1)
@@ -3902,6 +3944,7 @@
         case 0x13a:
             b = modrm;
             modrm = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             rm = modrm & 7;
             reg = ((modrm >> 3) & 7) | rex_r;
             mod = (modrm >> 6) & 3;
@@ -3919,6 +3962,7 @@
                     gen_lea_modrm(s, modrm, &reg_addr, &offset_addr);
                 reg = ((modrm >> 3) & 7) | rex_r;
                 val = ldub_code(s->pc++);
+                incLenOfLastInstr (s->tb, 1); // RJF
                 switch (b) {
                 case 0x14: /* pextrb */
                     tcg_gen_ld8u_tl(cpu_T[0], cpu_env, offsetof(CPUX86State,
@@ -4062,6 +4106,7 @@
                 }
             }
             val = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
 
             if ((b & 0xfc) == 0x60) { /* pcmpXstrX */
                 s->cc_op = CC_OP_EFLAGS;
@@ -4128,6 +4173,7 @@
             if (!(s->cpuid_ext2_features & CPUID_EXT2_3DNOW))
                 goto illegal_op;
             val = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             sse_op2 = sse_op_table5[val];
             if (!sse_op2)
                 goto illegal_op;
@@ -4137,7 +4183,8 @@
             break;
         case 0x70: /* pshufx insn */
         case 0xc6: /* pshufx insn */
-            val = ldub_code(s->pc++);
+           val = ldub_code(s->pc++);
+           incLenOfLastInstr (s->tb, 1); // RJF
             tcg_gen_addi_ptr(cpu_ptr0, cpu_env, op1_offset);
             tcg_gen_addi_ptr(cpu_ptr1, cpu_env, op2_offset);
             ((void (*)(TCGv_ptr, TCGv_ptr, TCGv_i32))sse_op2)(cpu_ptr0, cpu_ptr1, tcg_const_i32(val));
@@ -4145,6 +4192,7 @@
         case 0xc2:
             /* compare insns */
             val = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             if (val >= 8)
                 goto illegal_op;
             sse_op2 = sse_op_table4[val][b1];
@@ -4184,6 +4232,7 @@
     }
 }
 
+
 /* convert one instruction. s->is_jmp is set if the translation must
    be stopped. Return the next pc value */
 static target_ulong disas_insn(DisasContext *s, target_ulong pc_start)
@@ -4227,9 +4276,13 @@
     x86_64_hregs = 0;
 #endif
     s->rip_offset = 0; /* for relative ip address */
+#ifdef CONFIG_S2E              // RJF
+    s->tb->lenOfLastInstr = 0; // RJF
+#endif                         // RJF
  next_byte:
     b = ldub_code(s->pc);
     s->pc++;
+    incLenOfLastInstr (s->tb, 1); // RJF
     /* check prefixes */
 #ifdef TARGET_X86_64
     if (CODE64(s)) {
@@ -4346,6 +4399,7 @@
 #ifdef CONFIG_S2E
             uint64_t arg = ldq_code(s->pc);
             s2e_tcg_emit_custom_instruction(g_s2e, arg);
+            incLenOfLastInstr (s->tb, 8); // RJF matches s->pc+=8 5 lines below
 #else
             /* Simply skip the S2E opcodes when building vanilla qemu */
             ldq_code(s->pc);
@@ -4358,6 +4412,7 @@
         /**************************/
         /* extended op code */
         b = ldub_code(s->pc++) | 0x100;
+        incLenOfLastInstr (s->tb, 1); // RJF
         goto reswitch;
 
         /**************************/
@@ -4382,7 +4437,8 @@
 
             switch(f) {
             case 0: /* OP Ev, Gv */
-                modrm = ldub_code(s->pc++);
+               modrm = ldub_code(s->pc++);
+               incLenOfLastInstr (s->tb, 1); // RJF
                 reg = ((modrm >> 3) & 7) | rex_r;
                 mod = (modrm >> 6) & 3;
                 rm = (modrm & 7) | REX_B(s);
@@ -4404,7 +4460,8 @@
                 gen_op(s, op, ot, opreg);
                 break;
             case 1: /* OP Gv, Ev */
-                modrm = ldub_code(s->pc++);
+               modrm = ldub_code(s->pc++);
+               incLenOfLastInstr (s->tb, 1); // RJF
                 mod = (modrm >> 6) & 3;
                 reg = ((modrm >> 3) & 7) | rex_r;
                 rm = (modrm & 7) | REX_B(s);
@@ -4442,6 +4499,7 @@
                 ot = dflag + OT_WORD;
 
             modrm = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             mod = (modrm >> 6) & 3;
             rm = (modrm & 7) | REX_B(s);
             op = (modrm >> 3) & 7;
@@ -4491,6 +4549,7 @@
             ot = dflag + OT_WORD;
 
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         rm = (modrm & 7) | REX_B(s);
         op = (modrm >> 3) & 7;
@@ -4723,6 +4782,7 @@
             ot = dflag + OT_WORD;
 
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         rm = (modrm & 7) | REX_B(s);
         op = (modrm >> 3) & 7;
@@ -4774,7 +4834,7 @@
             gen_movtl_T1_im(next_eip);
             gen_push_T1(s);
             gen_op_jmp_T0(s);
-            gen_eob(s);
+            gen_eob(s, 0); // RJF bc T0 or next_eip?
             break;
         case 3: /* lcall Ev */
             SET_TB_TYPE(TB_CALL_IND);
@@ -4784,7 +4844,7 @@
             gen_op_ldu_T0_A0(OT_WORD + s->mem_index);
         do_lcall:
             if (s->pe && !s->vm86) {
-                if (s->cc_op != CC_OP_DYNAMIC)
+                //RJF if (s->cc_op != CC_OP_DYNAMIC)
                     gen_op_set_cc_op(s->cc_op);
                 gen_jmp_im(s, pc_start - s->cs_base);
                 tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T[0]);
@@ -4797,14 +4857,14 @@
                                       tcg_const_i32(dflag),
                                       tcg_const_i32(s->pc - s->cs_base));
             }
-            gen_eob(s);
+            gen_eob(s, pc_start - s->cs_base); // RJF
             break;
         case 4: /* jmp Ev */
             SET_TB_TYPE(TB_JMP_IND);
             if (s->dflag == 0)
                 gen_op_andl_T0_ffff();
             gen_op_jmp_T0(s);
-            gen_eob(s);
+            gen_eob(s, 0);
             break;
         case 5: /* ljmp Ev */
             SET_TB_TYPE(TB_JMP_IND);
@@ -4812,10 +4872,13 @@
             gen_add_A0_im(s, 1 << (ot - OT_WORD + 1));
             gen_op_ldu_T0_A0(OT_WORD + s->mem_index);
         do_ljmp:
+            s->pe = s->pe; // RJF so label works   
+            target_ulong nextPc = 0; // RJF
             if (s->pe && !s->vm86) {
                 if (s->cc_op != CC_OP_DYNAMIC)
                     gen_op_set_cc_op(s->cc_op);
                 gen_jmp_im(s, pc_start - s->cs_base);
+                nextPc = pc_start - s->cs_base; // RJF
                 tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T[0]);
                 gen_helper_ljmp_protected(cpu_tmp2_i32, cpu_T[1],
                                           tcg_const_i32(s->pc - pc_start));
@@ -4824,7 +4887,7 @@
                 gen_op_movl_T0_T1();
                 gen_op_jmp_T0(s);
             }
-            gen_eob(s);
+            gen_eob(s, nextPc); // RJF
             break;
         case 6: /* push Ev */
             gen_push_T0(s);
@@ -4842,6 +4905,7 @@
             ot = dflag + OT_WORD;
 
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         rm = (modrm & 7) | REX_B(s);
         reg = ((modrm >> 3) & 7) | rex_r;
@@ -4909,6 +4973,7 @@
     case 0x6b:
         ot = dflag + OT_WORD;
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         reg = ((modrm >> 3) & 7) | rex_r;
         if (b == 0x69)
             s->rip_offset = insn_const_size(ot);
@@ -4973,6 +5038,7 @@
         else
             ot = dflag + OT_WORD;
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         reg = ((modrm >> 3) & 7) | rex_r;
         mod = (modrm >> 6) & 3;
         if (mod == 3) {
@@ -5004,6 +5070,7 @@
             else
                 ot = dflag + OT_WORD;
             modrm = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             reg = ((modrm >> 3) & 7) | rex_r;
             mod = (modrm >> 6) & 3;
             t0 = tcg_temp_local_new();
@@ -5048,7 +5115,8 @@
         }
         break;
     case 0x1c7: /* cmpxchg8b */
-        modrm = ldub_code(s->pc++);
+       modrm = ldub_code(s->pc++);
+       incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         if ((mod == 3) || ((modrm & 0x38) != 0x8))
             goto illegal_op;
@@ -5123,6 +5191,7 @@
             ot = dflag + OT_WORD;
         }
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         gen_pop_T0(s);
         if (mod == 3) {
@@ -5143,7 +5212,9 @@
             int level;
             val = lduw_code(s->pc);
             s->pc += 2;
+            incLenOfLastInstr (s->tb, 2); // RJF
             level = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             gen_enter(s, val, level);
         }
         break;
@@ -5201,7 +5272,7 @@
         }
         if (s->is_jmp) {
             gen_jmp_im(s, s->pc - s->cs_base);
-            gen_eob(s);
+            gen_eob(s, s->pc - s->cs_base); // RJF
         }
         break;
     case 0x1a1: /* pop fs */
@@ -5211,7 +5282,7 @@
         gen_pop_update(s);
         if (s->is_jmp) {
             gen_jmp_im(s, s->pc - s->cs_base);
-            gen_eob(s);
+            gen_eob(s, s->pc - s->cs_base); // RJF
         }
         break;
 
@@ -5224,6 +5295,7 @@
         else
             ot = dflag + OT_WORD;
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         reg = ((modrm >> 3) & 7) | rex_r;
 
         /* generate a generic store */
@@ -5236,6 +5308,7 @@
         else
             ot = dflag + OT_WORD;
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         if (mod != 3) {
             s->rip_offset = insn_const_size(ot);
@@ -5255,13 +5328,15 @@
         else
             ot = OT_WORD + dflag;
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         reg = ((modrm >> 3) & 7) | rex_r;
 
         gen_ldst_modrm(s, modrm, ot, OR_TMP0, 0);
         gen_op_mov_reg_T0(ot, reg);
         break;
     case 0x8e: /* mov seg, Gv */
-        modrm = ldub_code(s->pc++);
+       modrm = ldub_code(s->pc++);
+       incLenOfLastInstr (s->tb, 1); // RJF
         reg = (modrm >> 3) & 7;
         if (reg >= 6 || reg == R_CS)
             goto illegal_op;
@@ -5277,11 +5352,12 @@
         }
         if (s->is_jmp) {
             gen_jmp_im(s, s->pc - s->cs_base);
-            gen_eob(s);
+            gen_eob(s, s->pc - s->cs_base); // RJF
         }
         break;
     case 0x8c: /* mov Gv, seg */
-        modrm = ldub_code(s->pc++);
+       modrm = ldub_code(s->pc++);
+       incLenOfLastInstr (s->tb, 1); // RJF
         reg = (modrm >> 3) & 7;
         mod = (modrm >> 6) & 3;
         if (reg >= 6)
@@ -5305,6 +5381,7 @@
             /* ot is the size of source */
             ot = (b & 1) + OT_BYTE;
             modrm = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             reg = ((modrm >> 3) & 7) | rex_r;
             mod = (modrm >> 6) & 3;
             rm = (modrm & 7) | REX_B(s);
@@ -5342,6 +5419,7 @@
     case 0x8d: /* lea */
         ot = dflag + OT_WORD;
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         if (mod == 3)
             goto illegal_op;
@@ -5370,6 +5448,7 @@
             if (s->aflag == 2) {
                 offset_addr = ldq_code(s->pc);
                 s->pc += 8;
+                incLenOfLastInstr (s->tb, 8); // RJF
                 gen_op_movq_A0_im(offset_addr);
             } else
 #endif
@@ -5426,6 +5505,7 @@
             /* 64 bit case */
             tmp = ldq_code(s->pc);
             s->pc += 8;
+            incLenOfLastInstr (s->tb, 8); // RJF
             reg = (b & 7) | REX_B(s);
             gen_movtl_T0_im(tmp);
             gen_op_mov_reg_T0(OT_QUAD, reg);
@@ -5452,6 +5532,7 @@
         else
             ot = dflag + OT_WORD;
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         reg = ((modrm >> 3) & 7) | rex_r;
         mod = (modrm >> 6) & 3;
         if (mod == 3) {
@@ -5495,6 +5576,7 @@
     do_lxx:
         ot = dflag ? OT_LONG : OT_WORD;
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         reg = ((modrm >> 3) & 7) | rex_r;
         mod = (modrm >> 6) & 3;
         if (mod == 3)
@@ -5509,7 +5591,7 @@
         gen_op_mov_reg_T1(ot, reg);
         if (s->is_jmp) {
             gen_jmp_im(s, s->pc - s->cs_base);
-            gen_eob(s);
+            gen_eob(s, s->pc - s->cs_base); // RJF
         }
         break;
 
@@ -5527,6 +5609,7 @@
                 ot = dflag + OT_WORD;
 
             modrm = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             mod = (modrm >> 6) & 3;
             op = (modrm >> 3) & 7;
 
@@ -5545,7 +5628,8 @@
                 gen_shift(s, op, ot, opreg, OR_ECX);
             } else {
                 if (shift == 2) {
-                    shift = ldub_code(s->pc++);
+                   shift = ldub_code(s->pc++);
+                   incLenOfLastInstr (s->tb, 1); // RJF
                 }
                 gen_shifti(s, op, ot, opreg, shift);
             }
@@ -5580,6 +5664,7 @@
     do_shiftd:
         ot = dflag + OT_WORD;
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         rm = (modrm & 7) | REX_B(s);
         reg = ((modrm >> 3) & 7) | rex_r;
@@ -5592,7 +5677,8 @@
         gen_op_mov_TN_reg(ot, 1, reg);
 
         if (shift) {
-            val = ldub_code(s->pc++);
+           val = ldub_code(s->pc++);
+           incLenOfLastInstr (s->tb, 1); // RJF
             tcg_gen_movi_tl(cpu_T3, val);
         } else {
             tcg_gen_mov_tl(cpu_T3, cpu_regs[R_ECX]);
@@ -5610,6 +5696,7 @@
             break;
         }
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         rm = modrm & 7;
         op = ((b & 7) << 3) | ((modrm >> 3) & 7);
@@ -6241,6 +6328,7 @@
         else
             ot = dflag ? OT_LONG : OT_WORD;
         val = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         gen_op_movl_T0_im(val);
         gen_check_io(s, ot, pc_start - s->cs_base,
                      SVM_IOIO_TYPE_MASK | svm_is_rep(prefixes));
@@ -6261,6 +6349,7 @@
         else
             ot = dflag ? OT_LONG : OT_WORD;
         val = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         gen_op_movl_T0_im(val);
         gen_check_io(s, ot, pc_start - s->cs_base,
                      svm_is_rep(prefixes));
@@ -6328,6 +6417,7 @@
         s2e_on_translate_jump_start(g_s2e, g_s2e_state, s->tb, s->pc, JT_RET);
         val = ldsw_code(s->pc);
         s->pc += 2;
+        incLenOfLastInstr (s->tb, 2); // RJF
         gen_pop_T0(s);
         if (CODE64(s) && s->dflag)
             s->dflag = 2;
@@ -6335,7 +6425,7 @@
         if (s->dflag == 0)
             gen_op_andl_T0_ffff();
         gen_op_jmp_T0(s);
-        gen_eob(s);
+        gen_eob(s, 0); // RJF
         break;
     case 0xc3: /* ret */
         SET_TB_TYPE(TB_RET);
@@ -6345,13 +6435,14 @@
         if (s->dflag == 0)
             gen_op_andl_T0_ffff();
         gen_op_jmp_T0(s);
-        gen_eob(s);
+        gen_eob(s, 0); // RJF
         break;
     case 0xca: /* lret im */
         SET_TB_TYPE(TB_RET);
         s2e_on_translate_jump_start(g_s2e, g_s2e_state, s->tb, s->pc, JT_LRET);
         val = ldsw_code(s->pc);
         s->pc += 2;
+        incLenOfLastInstr (s->tb, 2); // RJF
     do_lret:
         if (s->pe && !s->vm86) {
             if (s->cc_op != CC_OP_DYNAMIC)
@@ -6375,7 +6466,7 @@
             /* add stack offset */
             gen_stack_update(s, val + (4 << s->dflag));
         }
-        gen_eob(s);
+        gen_eob(s, 0); // RJF
         break;
     case 0xcb: /* lret */
         s2e_on_translate_jump_start(g_s2e, g_s2e_state, s->tb, s->pc, JT_LRET);
@@ -6404,7 +6495,7 @@
                                       tcg_const_i32(s->pc - s->cs_base));
             s->cc_op = CC_OP_EFLAGS;
         }
-        gen_eob(s);
+        gen_eob(s, pc_start - s->cs_base);  // RJF or 1st case might need to be 0
         break;
     case 0xe8: /* call im */
         {
@@ -6496,7 +6587,8 @@
         break;
 
     case 0x190 ... 0x19f: /* setcc Gv */
-        modrm = ldub_code(s->pc++);
+       modrm = ldub_code(s->pc++);
+       incLenOfLastInstr (s->tb, 1); // RJF
         gen_setcc(s, b);
         gen_ldst_modrm(s, modrm, OT_BYTE, OR_TMP0, 1);
         break;
@@ -6507,6 +6599,7 @@
 
             ot = dflag + OT_WORD;
             modrm = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             reg = ((modrm >> 3) & 7) | rex_r;
             mod = (modrm >> 6) & 3;
             t0 = tcg_temp_local_new();
@@ -6587,7 +6680,7 @@
             s->cc_op = CC_OP_EFLAGS;
             /* abort translation because TF flag may change */
             gen_jmp_im(s, s->pc - s->cs_base);
-            gen_eob(s);
+            gen_eob(s, s->pc - s->cs_base); // RJF
         }
         break;
     case 0x9e: /* sahf */
@@ -6647,6 +6740,7 @@
     case 0x1ba: /* bt/bts/btr/btc Gv, im */
         ot = dflag + OT_WORD;
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         op = (modrm >> 3) & 7;
         mod = (modrm >> 6) & 3;
         rm = (modrm & 7) | REX_B(s);
@@ -6659,6 +6753,7 @@
         }
         /* load shift */
         val = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         gen_op_movl_T1_im(val);
         if (op < 4)
             goto illegal_op;
@@ -6678,6 +6773,7 @@
     do_btx:
         ot = dflag + OT_WORD;
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         reg = ((modrm >> 3) & 7) | rex_r;
         mod = (modrm >> 6) & 3;
         rm = (modrm & 7) | REX_B(s);
@@ -6739,6 +6835,7 @@
 
             ot = dflag + OT_WORD;
             modrm = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             reg = ((modrm >> 3) & 7) | rex_r;
             gen_ldst_modrm(s,modrm, ot, OR_TMP0, 0);
             gen_extu(ot, cpu_T[0]);
@@ -6811,6 +6908,7 @@
         if (CODE64(s))
             goto illegal_op;
         val = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         if (val == 0) {
             gen_exception(s, EXCP00_DIVZ, pc_start - s->cs_base);
         } else {
@@ -6822,6 +6920,7 @@
         if (CODE64(s))
             goto illegal_op;
         val = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         gen_helper_aad(tcg_const_i32(val));
         s->cc_op = CC_OP_LOGICB;
         break;
@@ -6848,13 +6947,16 @@
         }
         break;
     case 0xcc: /* int3 */
+        SET_TB_TYPE(TB_INTERRUPT);                      // RJF
         gen_interrupt(s, EXCP03_INT3, pc_start - s->cs_base, s->pc - s->cs_base);
         break;
     case 0xcd: /* int N */
-        val = ldub_code(s->pc++);
+       val = ldub_code(s->pc++);
+       incLenOfLastInstr (s->tb, 1); // RJF
         if (s->vm86 && s->iopl != 3) {
             gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
         } else {
+            SET_TB_TYPE(TB_INTERRUPT);              // RJF
             gen_interrupt(s, val, pc_start - s->cs_base, s->pc - s->cs_base);
         }
         break;
@@ -6905,7 +7007,7 @@
                     gen_helper_set_inhibit_irq();
                 /* give a chance to handle pending irqs */
                 gen_jmp_im(s, s->pc - s->cs_base);
-                gen_eob(s);
+                gen_eob(s, s->pc - s->cs_base); // RJF
             } else {
                 gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
             }
@@ -6922,6 +7024,7 @@
             goto illegal_op;
         ot = dflag ? OT_LONG : OT_WORD;
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         reg = (modrm >> 3) & 7;
         mod = (modrm >> 6) & 3;
         if (mod == 3)
@@ -7010,7 +7113,7 @@
             gen_set_label(l1);
             gen_jmp_im(s, tval);
             gen_set_label(l2);
-            gen_eob(s);
+            gen_eob(s, next_eip); // RJF tval or next_eip?
         }
         break;
     case 0x130: /* wrmsr */
@@ -7057,9 +7160,10 @@
                 gen_op_set_cc_op(s->cc_op);
                 s->cc_op = CC_OP_DYNAMIC;
             }
+            SET_TB_TYPE(TB_SYSENTER);                      // RJF
             gen_jmp_im(s, pc_start - s->cs_base);
             gen_helper_sysenter();
-            gen_eob(s);
+            gen_eob(s, pc_start - s->cs_base); // RJF
         }
         break;
     case 0x135: /* sysexit */
@@ -7073,9 +7177,10 @@
                 gen_op_set_cc_op(s->cc_op);
                 s->cc_op = CC_OP_DYNAMIC;
             }
+            SET_TB_TYPE(TB_SYSEXIT);                      // RJF
             gen_jmp_im(s, pc_start - s->cs_base);
             gen_helper_sysexit(tcg_const_i32(dflag));
-            gen_eob(s);
+            gen_eob(s, pc_start - s->cs_base); // RJF
         }
         break;
 #ifdef TARGET_X86_64
@@ -7085,9 +7190,10 @@
             gen_op_set_cc_op(s->cc_op);
             s->cc_op = CC_OP_DYNAMIC;
         }
+        SET_TB_TYPE(TB_SYSENTER);                      // RJF
         gen_jmp_im(s, pc_start - s->cs_base);
         gen_helper_syscall(tcg_const_i32(s->pc - pc_start));
-        gen_eob(s);
+        gen_eob(s, pc_start - s->cs_base); // RJF
         break;
     case 0x107: /* sysret */
         if (!s->pe) {
@@ -7097,12 +7203,13 @@
                 gen_op_set_cc_op(s->cc_op);
                 s->cc_op = CC_OP_DYNAMIC;
             }
+            SET_TB_TYPE(TB_SYSEXIT);                      // RJF
             gen_jmp_im(s, pc_start - s->cs_base);
             gen_helper_sysret(tcg_const_i32(s->dflag));
             /* condition codes are modified only in long mode */
             if (s->lma)
                 s->cc_op = CC_OP_EFLAGS;
-            gen_eob(s);
+            gen_eob(s, pc_start - s->cs_base); // RJF
         }
         break;
 #endif
@@ -7124,7 +7231,8 @@
         }
         break;
     case 0x100:
-        modrm = ldub_code(s->pc++);
+       modrm = ldub_code(s->pc++);
+       incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         op = (modrm >> 3) & 7;
         switch(op) {
@@ -7192,7 +7300,8 @@
         }
         break;
     case 0x101:
-        modrm = ldub_code(s->pc++);
+       modrm = ldub_code(s->pc++);
+       incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         op = (modrm >> 3) & 7;
         rm = modrm & 7;
@@ -7243,7 +7352,7 @@
                     }
                     gen_jmp_im(s, pc_start - s->cs_base);
                     gen_helper_mwait(tcg_const_i32(s->pc - pc_start));
-                    gen_eob(s);
+                    gen_eob(s, pc_start - s->cs_base); // RJF
                     break;
                 default:
                     goto illegal_op;
@@ -7384,7 +7493,7 @@
                 gen_ldst_modrm(s, modrm, OT_WORD, OR_TMP0, 0);
                 gen_helper_lmsw(cpu_T[0]);
                 gen_jmp_im(s, s->pc - s->cs_base);
-                gen_eob(s);
+                gen_eob(s, s->pc - s->cs_base); // RJF
             }
             break;
         case 7:
@@ -7398,7 +7507,7 @@
                     gen_lea_modrm(s, modrm, &reg_addr, &offset_addr);
                     gen_helper_invlpg(cpu_A0);
                     gen_jmp_im(s, s->pc - s->cs_base);
-                    gen_eob(s);
+                    gen_eob(s, s->pc - s->cs_base); // RJF
                 }
             } else {
                 switch (rm) {
@@ -7463,6 +7572,7 @@
             d_ot = dflag + OT_WORD;
 
             modrm = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             reg = ((modrm >> 3) & 7) | rex_r;
             mod = (modrm >> 6) & 3;
             rm = (modrm & 7) | REX_B(s);
@@ -7495,6 +7605,7 @@
             t2 = tcg_temp_local_new();
             ot = OT_WORD;
             modrm = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             reg = (modrm >> 3) & 7;
             mod = (modrm >> 6) & 3;
             rm = modrm & 7;
@@ -7543,6 +7654,7 @@
                 goto illegal_op;
             ot = dflag ? OT_LONG : OT_WORD;
             modrm = ldub_code(s->pc++);
+            incLenOfLastInstr (s->tb, 1); // RJF
             reg = ((modrm >> 3) & 7) | rex_r;
             gen_ldst_modrm(s, modrm, OT_WORD, OR_TMP0, 0);
             t0 = tcg_temp_local_new();
@@ -7562,7 +7674,8 @@
         }
         break;
     case 0x118:
-        modrm = ldub_code(s->pc++);
+       modrm = ldub_code(s->pc++);
+       incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         op = (modrm >> 3) & 7;
         switch(op) {
@@ -7581,7 +7694,8 @@
         }
         break;
     case 0x119 ... 0x11f: /* nop (multi byte) */
-        modrm = ldub_code(s->pc++);
+       modrm = ldub_code(s->pc++);
+       incLenOfLastInstr (s->tb, 1); // RJF
         gen_nop_modrm(s, modrm);
         break;
     case 0x120: /* mov reg, crN */
@@ -7589,7 +7703,8 @@
         if (s->cpl != 0) {
             gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
         } else {
-            modrm = ldub_code(s->pc++);
+           modrm = ldub_code(s->pc++);
+           incLenOfLastInstr (s->tb, 1); // RJF
             if ((modrm & 0xc0) != 0xc0)
                 goto illegal_op;
             rm = (modrm & 7) | REX_B(s);
@@ -7615,7 +7730,7 @@
                     gen_op_mov_TN_reg(ot, 0, rm);
                     gen_helper_write_crN(tcg_const_i32(reg), cpu_T[0]);
                     gen_jmp_im(s, s->pc - s->cs_base);
-                    gen_eob(s);
+                    gen_eob(s, s->pc - s->cs_base); // RJF
                 } else {
                     gen_helper_read_crN(cpu_T[0], tcg_const_i32(reg));
                     gen_op_mov_reg_T0(ot, rm);
@@ -7631,7 +7746,8 @@
         if (s->cpl != 0) {
             gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
         } else {
-            modrm = ldub_code(s->pc++);
+           modrm = ldub_code(s->pc++);
+           incLenOfLastInstr (s->tb, 1); // RJF
             if ((modrm & 0xc0) != 0xc0)
                 goto illegal_op;
             rm = (modrm & 7) | REX_B(s);
@@ -7648,7 +7764,7 @@
                 gen_op_mov_TN_reg(ot, 0, rm);
                 gen_helper_movl_drN_T0(tcg_const_i32(reg), cpu_T[0]);
                 gen_jmp_im(s, s->pc - s->cs_base);
-                gen_eob(s);
+                gen_eob(s, s->pc - s->cs_base); // RJF
             } else {
                 gen_svm_check_intercept(s, pc_start, SVM_EXIT_READ_DR0 + reg);
                 tcg_gen_ld_tl(cpu_T[0], cpu_env, offsetof(CPUX86State,dr[reg]));
@@ -7664,7 +7780,7 @@
             gen_helper_clts();
             /* abort block because static cpu state changed */
             gen_jmp_im(s, s->pc - s->cs_base);
-            gen_eob(s);
+            gen_eob(s, s->pc - s->cs_base); // RJF
         }
         break;
     /* MMX/3DNow!/SSE/SSE2/SSE3/SSSE3/SSE4 support */
@@ -7673,6 +7789,7 @@
             goto illegal_op;
         ot = s->dflag == 2 ? OT_QUAD : OT_LONG;
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         if (mod == 3)
             goto illegal_op;
@@ -7681,7 +7798,8 @@
         gen_ldst_modrm(s, modrm, ot, reg, 1);
         break;
     case 0x1ae:
-        modrm = ldub_code(s->pc++);
+       modrm = ldub_code(s->pc++);
+       incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         op = (modrm >> 3) & 7;
         switch(op) {
@@ -7754,7 +7872,8 @@
         }
         break;
     case 0x10d: /* 3DNow! prefetch(w) */
-        modrm = ldub_code(s->pc++);
+       modrm = ldub_code(s->pc++);
+       incLenOfLastInstr (s->tb, 1); // RJF
         mod = (modrm >> 6) & 3;
         if (mod == 3)
             goto illegal_op;
@@ -7771,7 +7890,7 @@
         }
         gen_jmp_im(s, s->pc - s->cs_base);
         gen_helper_rsm();
-        gen_eob(s);
+        gen_eob(s, s->pc - s->cs_base); // RJF
         break;
     case 0x1b8: /* SSE4.2 popcnt */
         if ((prefixes & (PREFIX_REPZ | PREFIX_LOCK | PREFIX_REPNZ)) !=
@@ -7781,6 +7900,7 @@
             goto illegal_op;
 
         modrm = ldub_code(s->pc++);
+        incLenOfLastInstr (s->tb, 1); // RJF
         reg = ((modrm >> 3) & 7);
 
         if (s->prefix & PREFIX_DATA)
@@ -8035,6 +8155,7 @@
 
         s2e_on_translate_instruction_start(g_s2e, g_s2e_state, tb, pc_ptr);
         tb->pcOfLastInstr = pc_ptr;
+        tb->pcOfNextInstr = 0; // RJF explicit clear of var
         dc->useNextPc = 0;
         dc->nextPc = -1;
 
@@ -8054,7 +8175,7 @@
             dc->nextPc = new_pc_ptr - dc->cs_base;
             dc->useNextPc = 1;
         }
-        gen_instr_end(dc);
+        gen_instr_end(dc, dc->useNextPc ? dc->nextPc : new_pc_ptr); // RJF
 #endif
         pc_ptr = new_pc_ptr;
         num_insns++;
@@ -8070,7 +8191,7 @@
         if (dc->tf || dc->singlestep_enabled ||
             (flags & HF_INHIBIT_IRQ_MASK)) {
             gen_jmp_im(dc, pc_ptr - dc->cs_base);
-            gen_eob(dc);
+            gen_eob(dc, pc_ptr - dc->cs_base); // RJF
             break;
         }
         /* if too long translation, stop generation too */
@@ -8078,12 +8199,12 @@
             (pc_ptr - pc_start) >= (TARGET_PAGE_SIZE - 32) ||
             num_insns >= max_insns) {
             gen_jmp_im(dc, pc_ptr - dc->cs_base);
-            gen_eob(dc);
+            gen_eob(dc, pc_ptr - dc->cs_base); // RJF
             break;
         }
         if (singlestep) {
             gen_jmp_im(dc, pc_ptr - dc->cs_base);
-            gen_eob(dc);
+            gen_eob(dc, pc_ptr - dc->cs_base); // RJF
             break;
         }
     }

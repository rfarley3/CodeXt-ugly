--- /home/s2e/s2e/s2e/qemu/s2e/S2EExecutionState.cpp	2012-04-16 02:27:53.159226003 -0700
+++ EditedS2ESrcFiles/s2e-S2EExecutionState.cpp	2014-05-19 14:08:53.000000000 -0700
@@ -369,6 +369,25 @@
     }
 }
 
+void S2EExecutionState::writeCpuRegisterRaw (unsigned offset, klee::ref<klee::Expr> value) {
+    unsigned width = value->getWidth ();
+    assert ((width == 1 || (width & 7) == 0) && width <= 64);
+    assert (offset + Expr::getMinBytesForWidth (width) <= CPU_OFFSET (eip) );
+
+    if(!m_runningConcrete || !m_cpuRegistersObject->isConcrete (offset, width) ) {
+        m_cpuRegistersObject->write (offset, value);
+
+    } else if (isa<ConstantExpr>(value) ) {
+        ConstantExpr* ce = cast<ConstantExpr>(value);
+        uint64_t v = ce->getZExtValue (64);
+        small_memcpy ((void*) (m_cpuRegistersState->address + offset), (void*) &v,
+                    Expr::getMinBytesForWidth (ce->getWidth() ) );
+    }
+	 else { // RJF sic dragonus. just try it anyways!  TODO, this may no longer be necessary, try removing it
+        m_cpuRegistersObject->write (offset, value);
+	 }
+}
+
 bool S2EExecutionState::readCpuRegisterConcrete(unsigned offset,
                                                 void* buf, unsigned size)
 {
@@ -926,9 +945,18 @@
                     op.second = wos = addressSpace.getWriteable(
                                                     op.first, op.second);
                 }
+					 klee::ref<klee::Expr> e = wos->read8 (page_offset + i); // get expr before any solvers applied // RJF
                 buf[i] = g_s2e->getExecutor()->toConstant(*this, wos->read8(page_offset+i),
                        "memory access from concrete code")->getZExtValue(8);
                 wos->write8(page_offset+i, buf[i]);
+				    if (!isa<ConstantExpr> (e) ) { // catch the case if toConstant silently concretized Expr // RJF
+						 // we need to convert the QEMU host physical address to the guest process's virtual address // RJF
+						 // assumes PC and read are in the same page, if so, then page_offset + i is the last part of the guest proc virt address // RJF
+						 uint64_t addr = (getPc () & 0xfffffffffffff000) + (page_addr & 0xfff) + page_offset + i; // RJF
+					    //g_s2e->getDebugStream (this) << " PC 0x" << std::hex << getPc() << " pg_off+i 0x" << page_offset + i << " pg_addr: 0x" << page_addr << " addr: 0x" << addr << " i: " << i << " size: " << size << " readRamConcrete: e was concretized\n"; // RJF
+						 // void s2e_on_silent_concretize_new (address_that_was_concretized, expression_that_was_concretized, resulting_concretized_value, reason_for_concretization); //RJF
+						 s2e_on_silent_concretize (addr, (void*) e.get(), buf[i], "memory access from concrete code [new]"); // RJF
+					 }
             }
         }
     } else {

--- /home/s2e/s2e/s2e/guest/include/s2e.h	2012-04-16 02:27:52.749226000 -0700
+++ EditedS2ESrcFiles/guestinclude-s2e.h	2014-08-31 18:18:29.000000000 -0700
@@ -347,6 +347,74 @@
     return res;
 }
 
+/** CodeXt plugin */
+/** Communicates to S2E the coordinates of shellcode within memory and information about the associated process */
+static inline void s2e_codext_init (unsigned base, unsigned size, unsigned eip, unsigned sysc) {
+    __asm__ __volatile__(
+        ".byte 0x0f, 0x3f\n"                 // means s2e custom instruction is coming
+        ".byte 0x00, 0xFA, 0x01, 0x00\n"     // XX XX unique per plugin, YY YY YY YY YY YY per custom instruction within plugin
+        ".byte 0x00, 0x00, 0x00, 0x00\n"
+        : : "a" (base), "b" (size), "c" (eip), "d" (sysc)
+    );
+} // end fn s2e_codext_init
+
+
+/** Communicates to S2E that a process wants to be monitored */
+static inline void s2e_codext_init_lua () {
+    __asm__ __volatile__(
+        ".byte 0x0f, 0x3f\n"                 // means s2e custom instruction is coming
+        ".byte 0x00, 0xFA, 0x08, 0x00\n"     // XX XX unique per plugin, YY YY YY YY YY YY per custom instruction within plugin
+        ".byte 0x00, 0x00, 0x00, 0x00\n"
+    );
+} // end fn s2e_codext_init
+
+   //__s2e_touch_buffer (addr, size);
+/** Tells S2E to fuzz a variable */
+static inline unsigned s2e_codext_fuzz (unsigned start, unsigned end) {
+   unsigned retval;
+   __asm__ __volatile__(
+      ".byte 0x0f, 0x3f\n"                 // means s2e custom instruction is coming
+      ".byte 0x00, 0xFA, 0x02, 0x00\n"     // XX XX unique per plugin, YY YY YY YY YY YY per custom instruction within plugin
+      ".byte 0x00, 0x00, 0x00, 0x00\n"
+      : "=a" (retval) : "a" (0), "b" (start), "c" (end) // 1st : is output, 2nd : is input, specify registers (do not specify size modifiers) for the variables
+   );
+   return retval;
+} // end fn s2e_codext_fuzz
+
+
+// static inline unsigned int s2e_codext_createFork (unsigned int value)
+// return 2 states, state0 set to 0xffffffff and state1 set to value
+/** Tells S2E to fork a variable with a particular value*/
+static inline unsigned s2e_codext_createFork (unsigned value) {
+   unsigned retval;
+   __asm__ __volatile__(
+      ".byte 0x0f, 0x3f\n"                 // means s2e custom instruction is coming
+      ".byte 0x00, 0xFA, 0x04, 0x00\n"     // XX XX unique per plugin, YY YY YY YY YY YY per custom instruction within plugin
+      ".byte 0x00, 0x00, 0x00, 0x00\n"
+      : "=a" (retval) : "a" (0), "b" (value) // 1st : is output, 2nd : is input, specify registers (do not specify size modifiers) for the variables
+      );
+      return retval;
+} // end fn s2e_codext_fuzz
+
+
+static inline void s2e_codext_fini () {
+   __asm__ __volatile__(
+      ".byte 0x0f, 0x3f\n"                 // means s2e custom instruction is coming
+      ".byte 0x00, 0xFA, 0x06, 0x00\n"     // XX XX unique per plugin, YY YY YY YY YY YY per custom instruction within plugin
+      ".byte 0x00, 0x00, 0x00, 0x00\n"
+   );
+} // end fn s2e_codext_fini
+
+
+static inline void s2e_codext_enableMultiple () {
+   __asm__ __volatile__(
+      ".byte 0x0f, 0x3f\n"                 // means s2e custom instruction is coming
+      ".byte 0x00, 0xFA, 0x07, 0x00\n"     // XX XX unique per plugin, YY YY YY YY YY YY per custom instruction within plugin
+      ".byte 0x00, 0x00, 0x00, 0x00\n"
+   );
+} // end fn s2e_codext_enableMultiple
+
+
 /** Raw monitor plugin */
 /** Communicates to S2E the coordinates of loaded modules. Useful when there is
     no plugin to automatically parse OS data structures */
@@ -551,3 +619,6 @@
     return x;
   }
 }
+
+
+

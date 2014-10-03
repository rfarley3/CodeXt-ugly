--- /home/s2e/s2e/s2e/klee/include/klee/Constraints.h	2011-01-24 01:15:11.579830005 -0800
+++ EditedS2ESrcFiles/klee-Constraints.h	2014-06-09 21:10:43.000000000 -0700
@@ -44,7 +44,11 @@
   ref<Expr> simplifyExpr(ref<Expr> e) const;
 
   void addConstraint(ref<Expr> e);
-  
+
+  void clear() {
+    return constraints.clear();
+  }
+
   bool empty() const {
     return constraints.empty();
   }

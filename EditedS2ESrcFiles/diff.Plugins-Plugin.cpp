--- /home/s2e/s2e/s2e/qemu/s2e/Plugin.cpp	2012-04-16 02:27:52.769226001 -0700
+++ EditedS2ESrcFiles/Plugins-Plugin.cpp	2014-03-25 07:33:05.000000000 -0700
@@ -39,6 +39,13 @@
 #include <s2e/S2EExecutionState.h>
 #include <s2e/Utils.h>
 
+// RJF
+#include <s2e/Plugins/InterruptMonitor.h>
+#include <s2e/Plugins/LinuxSyscallMonitor.h>
+//#include <s2e/Plugins/SyscallTracker.h>
+#include <s2e/Plugins/CodeXt.h>
+// end RJF
+
 #include <algorithm>
 #include <assert.h>
 

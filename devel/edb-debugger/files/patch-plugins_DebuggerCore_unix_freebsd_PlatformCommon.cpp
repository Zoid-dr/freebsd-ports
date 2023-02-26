--- plugins/DebuggerCore/unix/freebsd/PlatformCommon.cpp.orig	2020-12-14 01:01:38 UTC
+++ plugins/DebuggerCore/unix/freebsd/PlatformCommon.cpp
@@ -1,2 +1,32 @@
 
 #include "PlatformCommon.h"
+#include <fstream>
+#include <iostream>
+#include <sys/signal.h>
+#include <sys/wait.h>
+
+
+namespace DebuggerCorePlugin {
+
+/**
+ * @brief resume_code
+ * @param status
+ * @return
+ */
+int resume_code(int status) {
+
+	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
+		return 0;
+	}
+
+	if (WIFSIGNALED(status)) {
+		return WTERMSIG(status);
+	}
+
+	if (WIFSTOPPED(status)) {
+		return WSTOPSIG(status);
+	}
+
+	return 0;
+}
+}

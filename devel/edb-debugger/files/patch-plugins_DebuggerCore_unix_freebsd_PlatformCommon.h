--- plugins/DebuggerCore/unix/freebsd/PlatformCommon.h.orig	2020-12-14 01:01:38 UTC
+++ plugins/DebuggerCore/unix/freebsd/PlatformCommon.h
@@ -2,4 +2,17 @@
 #ifndef PLATFORM_COMMON_H_20181225_
 #define PLATFORM_COMMON_H_20181225_
 
+#include "OSTypes.h"
+#include "edb.h"
+
+class QString;
+
+namespace DebuggerCorePlugin {
+
+
+	int resume_code(int status);
+
+}
+
+
 #endif

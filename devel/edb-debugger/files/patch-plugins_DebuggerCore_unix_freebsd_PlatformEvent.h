--- plugins/DebuggerCore/unix/freebsd/PlatformEvent.h.orig	2020-12-14 01:01:38 UTC
+++ plugins/DebuggerCore/unix/freebsd/PlatformEvent.h
@@ -21,6 +21,7 @@ along with this program.  If not, see <http://www.gnu.
 
 #include "IDebugEvent.h"
 #include <QCoreApplication>
+#include <signal.h> // for the SIG* definitions
 
 namespace DebuggerCorePlugin {
 
@@ -35,14 +36,14 @@ class PlatformEvent : IDebugEvent { (public)
 	PlatformEvent *clone() const override;
 
 public:
-	Message error_description() const override;
+	Message errorDescription() const override;
 	REASON reason() const override;
-	TRAP_REASON trap_reason() const override;
+	TRAP_REASON trapReason() const override;
 	bool exited() const override;
-	bool is_error() const override;
-	bool is_kill() const override;
-	bool is_stop() const override;
-	bool is_trap() const override;
+	bool isError() const override;
+	bool isKill() const override;
+	bool isStop() const override;
+	bool isTrap() const override;
 	bool terminated() const override;
 	bool stopped() const override;
 	edb::pid_t process() const override;
@@ -50,6 +51,10 @@ class PlatformEvent : IDebugEvent { (public)
 	int64_t code() const override;
 
 private:
+	static IDebugEvent::Message createUnexpectedSignalMessage(const QString &name, int number);
+
+private:
+	siginfo_t siginfo_ = {};
 	int status;
 	edb::pid_t pid;
 	edb::tid_t tid;

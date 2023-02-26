--- plugins/DebuggerCore/unix/freebsd/PlatformProcess.h.orig	2020-12-14 01:01:38 UTC
+++ plugins/DebuggerCore/unix/freebsd/PlatformProcess.h
@@ -20,46 +20,55 @@ along with this program.  If not, see <http://www.gnu.
 #define PLATFORM_PROCESS_H_20150517_
 
 #include "IProcess.h"
+#include "PlatformThread.h"
+namespace DebuggerCorePlugin {
 
-class PlatformProcess : public IProcess {
+class DebuggerCore;
+
+class PlatformProcess final : public IProcess {
+	Q_DECLARE_TR_FUNCTIONS(PlatformProcess)
+
 public:
 	// legal to call when not attached
-	QDateTime start_time() const override;
+	QDateTime startTime() const override;
 	QList<QByteArray> arguments() const override;
-	QString current_working_directory() const override;
+	QString currentWorkingDirectory() const override;
 	QString executable() const override;
 	edb::pid_t pid() const override;
 	std::shared_ptr<IProcess> parent() const override;
-	edb::address_t code_address() const override;
-	edb::address_t data_address() const override;
-	edb::address_t entry_point() const override;
+	edb::address_t codeAddress() const override;
+	edb::address_t dataAddress() const override;
+	edb::address_t entryPoint() const override;
 	QList<std::shared_ptr<IRegion>> regions() const override;
 	edb::uid_t uid() const override;
 	QString user() const override;
 	QString name() const override;
-	QList<Module> loaded_modules() const override;
+	QList<Module> loadedModules() const override;
 
 public:
-	edb::address_t debug_pointer() const override;
-	edb::address_t calculate_main() const override;
+	edb::address_t debugPointer() const override;
+	edb::address_t calculateMain() const override;
 
 public:
 	// only legal to call when attached
 	QList<std::shared_ptr<IThread>> threads() const override;
-	std::shared_ptr<IThread> current_thread() const override;
-	void set_current_thread(IThread &thread) override;
-	std::size_t write_bytes(edb::address_t address, const void *buf, size_t len) override;
-	std::size_t patch_bytes(edb::address_t address, const void *buf, size_t len) override;
-	std::size_t read_bytes(edb::address_t address, void *buf, size_t len) const override;
-	std::size_t read_pages(edb::address_t address, void *buf, size_t count) const override;
+	std::shared_ptr<IThread> currentThread() const override;
+	void setCurrentThread(IThread &thread) override;
+	std::size_t writeBytes(edb::address_t address, const void *buf, size_t len) override;
+	std::size_t patchBytes(edb::address_t address, const void *buf, size_t len) override;
+	std::size_t readBytes(edb::address_t address, void *buf, size_t len) const override;
+	std::size_t readPages(edb::address_t address, void *buf, size_t count) const override;
 	Status pause() override;
-	Status resume(edb::EVENT_STATUS status) override;
-	Status step(edb::EVENT_STATUS status) override;
+	Status resume(edb::EventStatus status) override;
+	Status step(edb::EventStatus status) override;
 	bool isPaused() const override;
 	QMap<edb::address_t, Patch> patches() const override;
 
 private:
+	DebuggerCore *core_ = nullptr;
+	QMap<edb::address_t, Patch> patches_;
 	edb::pid_t pid_;
 };
 
+}
 #endif

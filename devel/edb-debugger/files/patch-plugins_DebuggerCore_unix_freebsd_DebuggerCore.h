--- plugins/DebuggerCore/unix/freebsd/DebuggerCore.h.orig	2020-12-14 01:01:38 UTC
+++ plugins/DebuggerCore/unix/freebsd/DebuggerCore.h
@@ -21,10 +21,20 @@ along with this program.  If not, see <http://www.gnu.
 
 #include "DebuggerCoreBase.h"
 #include <QHash>
+#include "PlatformThread.h"
+#include <set>
+#include <csignal>
+#include <set>
+#include <unistd.h>
 
+class IBinary;
+class Status;
+
 namespace DebuggerCorePlugin {
 
-class DebuggerCore : public DebuggerCoreBase {
+class PlatformThread;
+
+class DebuggerCore final : public DebuggerCoreBase {
 	Q_OBJECT
 	Q_PLUGIN_METADATA(IID "edb.IDebugger/1.0")
 	Q_INTERFACES(IDebugger)
@@ -33,21 +43,24 @@ class DebuggerCore : public DebuggerCoreBase {
 	friend class PlatformProcess;
 	friend class PlatformThread;
 
+	CpuMode cpuMode() const override { return cpuMode_; }
+
 public:
 	DebuggerCore();
 	~DebuggerCore() override;
 
 public:
-	std::size_t pointer_size() const override;
-	size_t page_size() const override;
-	bool has_extension(quint64 ext) const override;
-	std::shared_ptr<IDebugEvent> wait_debug_event(int msecs) override;
+	MeansOfCapture lastMeansOfCapture() const override;
+	std::size_t pointerSize() const override;
+	size_t pageSize() const override;
+	bool hasExtension(uint64_t ext) const override;
+	std::shared_ptr<IDebugEvent> waitDebugEvent(std::chrono::milliseconds msecs) override;
 	Status attach(edb::pid_t pid) override;
 	Status detach() override;
 	void kill() override;
-	Status open(const QString &path, const QString &cwd, const QList<QByteArray> &args, const QString &tty) override;
-	MeansOfCapture lastMeansOfCapture() const override;
-	void set_ignored_exceptions(const QList<qlonglong> &exceptions) override;
+	Status open(const QString &path, const QString &cwd, const QList<QByteArray> &args, const QString &input, const QString &output) override;
+	void setIgnoredExceptions(const QList<qlonglong> &exceptions) override;
+	uint8_t nopFillByte() const override;
 
 public:
 	QMap<qlonglong, QString> exceptions() const override;
@@ -55,22 +68,22 @@ class DebuggerCore : public DebuggerCoreBase {
 	qlonglong exceptionValue(const QString &name) override;
 
 public:
-	edb::pid_t parent_pid(edb::pid_t pid) const override;
+	edb::pid_t parentPid(edb::pid_t pid) const override;
 
 public:
-	std::unique_ptr<IState> create_state() const override;
+	std::unique_ptr<IState> createState() const override;
 
 public:
-	quint64 cpu_type() const override;
+	uint64_t cpuType() const override;
 
 private:
-	QMap<edb::pid_t, std::shared_ptr<IProcess>> enumerate_processes() const override;
+	QMap<edb::pid_t, std::shared_ptr<IProcess>> enumerateProcesses() const override;
 
 public:
-	QString stack_pointer() const override;
-	QString frame_pointer() const override;
-	QString instruction_pointer() const override;
-	QString flag_register() const override;
+	QString stackPointer() const override;
+	QString framePointer() const override;
+	QString instructionPointer() const override;
+	QString flagRegister() const override;
 
 public:
 	IProcess *process() const override;
@@ -78,8 +91,15 @@ class DebuggerCore : public DebuggerCoreBase {
 private:
 	virtual long read_data(edb::address_t address, bool *ok);
 	virtual bool write_data(edb::address_t address, long value);
+	std::shared_ptr<IDebugEvent> handleEvent(edb::tid_t tid, int status);
+	void detectCpuMode();
+	void reset();
+	void pause();
 
 private:
+	using threads_type = QHash<edb::tid_t, std::shared_ptr<PlatformThread>>;
+
+private:
 	struct thread_info {
 	public:
 		thread_info() = default;
@@ -93,7 +113,12 @@ class DebuggerCore : public DebuggerCoreBase {
 	using threadmap_t = QHash<edb::tid_t, thread_info>;
 
 	edb::address_t page_size_;
-	threadmap_t threads_;
+	threads_type threads_;
+	std::set<edb::tid_t> waitedThreads_;
+	std::size_t pointerSize_ = sizeof(void *);
+	CpuMode cpuMode_                   = CpuMode::Unknown;
+	edb::tid_t activeThread_;
+	std::shared_ptr<IProcess> process_;
 };
 
 }

--- plugins/DebuggerCore/unix/freebsd/PlatformProcess.cpp.orig	2020-12-14 01:01:38 UTC
+++ plugins/DebuggerCore/unix/freebsd/PlatformProcess.cpp
@@ -17,6 +17,12 @@ along with this program.  If not, see <http://www.gnu.
 */
 
 #include "PlatformProcess.h"
+#include "Module.h"
+#include "edb.h"
+#include "IRegion.h"
+#include "PlatformRegion.h"
+#include "DebuggerCore.h"
+#include "QtHelper.h"
 #include <fcntl.h>
 #include <kvm.h>
 #include <machine/reg.h>
@@ -30,6 +36,18 @@ along with this program.  If not, see <http://www.gnu.
 #include <sys/wait.h>
 #include <unistd.h>
 
+#include <QByteArray>
+#include <QDateTime>
+#include <QDebug>
+#include <QFile>
+#include <QFileInfo>
+#include <QTextStream>
+
+#include <elf.h>
+#include <Util.h>
+#include <util/Container.h>
+
+
 namespace DebuggerCorePlugin {
 
 QString PlatformProcess::executable() const {
@@ -37,28 +55,95 @@ QString PlatformProcess::executable() const {
 	return QString();
 }
 
-QString PlatformProcess::current_working_directory() const {
+QString PlatformProcess::currentWorkingDirectory() const {
 	// TODO(eteran): implement this
 	return QString();
 }
 
-QDateTime PlatformProcess::start_time() const {
+QDateTime PlatformProcess::startTime() const {
 	// TODO(eteran): implement this
 	return QDateTime();
 }
 
-QList<Module> PlatformProcess::loaded_modules() const {
-	QList<Module> modules;
-	// TODO(eteran): implement this
-	return modules;
+/**
+ * @brief get_loaded_modules
+ * @param process
+ * @return
+ */
+template <class Addr>
+QList<Module> get_loaded_modules(const IProcess *process) {
+	QList<Module> ret;
+	return ret;
 }
 
-edb::address_t PlatformProcess::code_address() const {
+/**
+ * @brief PlatformProcess::setCurrentThread
+ * @param thread
+ */
+void PlatformProcess::setCurrentThread(IThread &thread) {
+	core_->activeThread_ = static_cast<PlatformThread *>(&thread)->tid();
+	edb::v1::update_ui();
+}
+
+/**
+ * @brief PlatformProcess::uid
+ * @return
+ */
+edb::uid_t PlatformProcess::uid() const {
+
+	const QFileInfo info(QString("/proc/%1").arg(pid_));
+	return info.ownerId();
+}
+
+/**
+ * @brief PlatformProcess::user
+ * @return
+ */
+QString PlatformProcess::user() const {
+	return QString();
+}
+
+/**
+ * @brief PlatformProcess::name
+ * @return
+ */
+QString PlatformProcess::name() const {
+	return QString();
+}
+
+
+QList<Module> PlatformProcess::loadedModules() const {
+	if (edb::v1::debuggeeIs64Bit()) {
+		return get_loaded_modules<Elf64_Addr>(this);
+	} else if (edb::v1::debuggeeIs32Bit()) {
+		return get_loaded_modules<Elf32_Addr>(this);
+	} else {
+		return QList<Module>();
+	}
+}
+
+/**
+ * @brief PlatformProcess::pid
+ * @return
+ */
+edb::pid_t PlatformProcess::pid() const {
+	return pid_;
+}
+
+/**
+ * @brief PlatformProcess::parent
+ * @return
+ */
+std::shared_ptr<IProcess> PlatformProcess::parent() const {
+	return nullptr;
+}
+
+edb::address_t PlatformProcess::codeAddress() const {
 	// TODO(eteran): implement this
 	return 0;
 }
 
-edb::address_t PlatformProcess::data_address() const {
+edb::address_t PlatformProcess::dataAddress() const {
 	// TODO(eteran): implement this
 	return 0;
 }
@@ -78,7 +163,7 @@ QList<std::shared_ptr<IRegion>> PlatformProcess::regio
 		memset(&vm_entry, 0, sizeof(vm_entry));
 		vm_entry.pve_entry = 0;
 
-		while (ptrace(PT_VM_ENTRY, pid_, reinterpret_cast<char *>(&vm_entry), NULL) == 0) {
+		while (ptrace(PT_VM_ENTRY, pid_, reinterpret_cast<char *>(&vm_entry), 0) == 0) {
 			vm_entry.pve_path    = buffer;
 			vm_entry.pve_pathlen = sizeof(buffer);
 
@@ -94,6 +179,248 @@ QList<std::shared_ptr<IRegion>> PlatformProcess::regio
 	}
 
 	return regions;
+}
+
+/**
+ * @brief PlatformProcess::isPaused
+ * @return true if ALL threads are currently in the debugger's wait list
+ */
+bool PlatformProcess::isPaused() const {
+	for (auto &thread : threads()) {
+		if (!thread->isPaused()) {
+			return false;
+		}
+	}
+
+	return true;
+}
+
+/**
+ * @brief PlatformProcess::patches
+ * @return any patches applied to this process
+ */
+QMap<edb::address_t, Patch> PlatformProcess::patches() const {
+	return patches_;
+}
+
+/**
+ * @brief PlatformProcess::entry_point
+ * @return
+ */
+edb::address_t PlatformProcess::entryPoint() const {
+		return edb::address_t{};
+}
+
+/**
+ * attempts to locate the ELF debug pointer in the target process and returns
+ * it, 0 of not found
+ *
+ * @brief PlatformProcess::debug_pointer
+ * @return
+ */
+edb::address_t PlatformProcess::debugPointer() const {
+	return edb::address_t{};
+}
+
+edb::address_t PlatformProcess::calculateMain() const {
+		return 0;
+}
+
+/**
+ * @brief PlatformProcess::threads
+ * @return
+ */
+QList<std::shared_ptr<IThread>> PlatformProcess::threads() const {
+
+	Q_ASSERT(core_->process_.get() == this);
+
+	QList<std::shared_ptr<IThread>> threadList;
+	threadList.reserve(core_->threads_.size());
+	std::copy(core_->threads_.begin(), core_->threads_.end(), std::back_inserter(threadList));
+	return threadList;
+}
+
+/**
+ * @brief PlatformProcess::currentThread
+ * @return
+ */
+std::shared_ptr<IThread> PlatformProcess::currentThread() const {
+
+	Q_ASSERT(core_->process_.get() == this);
+
+	auto it = core_->threads_.find(core_->activeThread_);
+	if (it != core_->threads_.end()) {
+		return it.value();
+	}
+	return nullptr;
+}
+
+/**
+ * writes <len> bytes from <buf> starting at <address>
+ *
+ * @brief PlatformProcess::writeBytes
+ * @param address
+ * @param buf
+ * @param len
+ * @return
+ */
+std::size_t PlatformProcess::writeBytes(edb::address_t address, const void *buf, std::size_t len) {
+	quint64 written = 0;
+
+	return written;
+}
+
+/**
+ * same as writeBytes, except that it also records the original data that was
+ * found at the address being written to.
+ *
+ * @brief PlatformProcess::patchBytes
+ * @param address
+ * @param buf
+ * @param len
+ * @return
+ */
+std::size_t PlatformProcess::patchBytes(edb::address_t address, const void *buf, size_t len) {
+
+	// NOTE(eteran): Unlike the read_bytes, write_bytes functions, this will
+	//               not apply the write if we could not properly backup <len>
+	//               bytes as requested.
+	// NOTE(eteran): On the off chance that we can READ <len> bytes, but can't
+	//               WRITE <len> bytes, we will return the number of bytes
+	//               written, but record <len> bytes of patch data.
+
+	Q_ASSERT(buf);
+	Q_ASSERT(core_->process_.get() == this);
+
+	Patch patch;
+	patch.address = address;
+	patch.origBytes.resize(len);
+	patch.newBytes = QByteArray(static_cast<const char *>(buf), len);
+
+	size_t read_ret = readBytes(address, patch.origBytes.data(), len);
+	if (read_ret != len) {
+		return 0;
+	}
+
+	patches_.insert(address, patch);
+
+	return writeBytes(address, buf, len);
+}
+
+/**
+ * reads <len> bytes into <buf> starting at <address>
+ *
+ * @brief PlatformProcess::readBytes
+ * @param address
+ * @param buf
+ * @param len
+ * @return
+ */
+std::size_t PlatformProcess::readBytes(edb::address_t address, void *buf, std::size_t len) const {
+	quint64 read = 0;
+	return read;
+}
+
+/**
+ * reads <count> pages from the process starting at <address>
+ *
+ * @brief PlatformProcess::readPages
+ * @param address - must be page aligned.
+ * @param buf - sizeof(buf) must be >= count * core_->page_size()
+ * @param count - number of pages
+ * @return
+ */
+std::size_t PlatformProcess::readPages(edb::address_t address, void *buf, std::size_t count) const {
+	Q_ASSERT(buf);
+	Q_ASSERT(core_->process_.get() == this);
+	return readBytes(address, buf, count * core_->pageSize()) / core_->pageSize();
+}
+
+/**
+ * stops *all* threads of a process
+ *
+ * @brief PlatformProcess::pause
+ * @return
+ */
+Status PlatformProcess::pause() {
+	// belive it or not, I belive that this is sufficient for all threads.
+	// This is because in the debug event handler, a SIGSTOP is sent
+	// to all threads when any event arrives, so no need to explicitly do
+	// it here. We just need any thread to stop. So we'll just target the
+	// pid_ which will send it to any one of the threads in the process.
+	if (::kill(pid_, SIGSTOP) == -1) {
+		const char *const strError = strerror(errno);
+		qWarning() << "Unable to pause process" << pid_ << ": kill(SIGSTOP) failed:" << strError;
+		return Status(strError);
+	}
+
+	return Status::Ok;
+}
+
+/**
+ * resumes ALL threads
+ *
+ * @brief PlatformProcess::resume
+ * @param status
+ * @return
+ */
+Status PlatformProcess::resume(edb::EventStatus status) {
+
+	// NOTE(eteran): OK, this is very tricky. When the user wants to resume
+	// while ignoring a signal (DEBUG_CONTINUE), we need to know which thread
+	// needs to have the signal ignored, and which need to have their signals
+	// passed during the resume
+
+	// TODO: assert that we are paused
+	Q_ASSERT(core_->process_.get() == this);
+
+	QString errorMessage;
+
+	if (status != edb::DEBUG_STOP) {
+
+		if (std::shared_ptr<IThread> thread = currentThread()) {
+			const auto resumeStatus = thread->resume(status);
+			if (!resumeStatus) {
+				errorMessage += tr("Failed to resume thread %1: %2\n").arg(thread->tid()).arg(resumeStatus.error());
+			}
+
+			// resume the other threads passing the signal they originally reported had
+			for (auto &other_thread : threads()) {
+				if (util::contains(core_->waitedThreads_, other_thread->tid())) {
+					const auto resumeStatus = other_thread->resume();
+					if (!resumeStatus) {
+						errorMessage += tr("Failed to resume thread %1: %2\n").arg(thread->tid()).arg(resumeStatus.error());
+					}
+				}
+			}
+		}
+	}
+
+	if (errorMessage.isEmpty()) {
+		return Status::Ok;
+	}
+
+	qWarning() << errorMessage.toStdString().c_str();
+	return Status("\n" + errorMessage);
+}
+
+/**
+ * steps the currently active thread
+ *
+ * @brief PlatformProcess::step
+ * @param status
+ * @return
+ */
+Status PlatformProcess::step(edb::EventStatus status) {
+	// TODO: assert that we are paused
+	Q_ASSERT(core_->process_.get() == this);
+
+	if (status != edb::DEBUG_STOP) {
+		if (std::shared_ptr<IThread> thread = currentThread()) {
+			return thread->step(status);
+		}
+	}
+	return Status::Ok;
 }
 
 }

--- plugins/DebuggerCore/unix/freebsd/DebuggerCore.cpp.orig	2020-12-14 01:01:38 UTC
+++ plugins/DebuggerCore/unix/freebsd/DebuggerCore.cpp
@@ -20,11 +20,15 @@ along with this program.  If not, see <http://www.gnu.
 #include "PlatformEvent.h"
 #include "PlatformRegion.h"
 #include "PlatformState.h"
+#include "PlatformProcess.h"
 #include "State.h"
+#include "Types.h"
 #include "string_hash.h"
 
 #include <QDebug>
 #include <QMessageBox>
+#include <QDir>
+#include <QSettings>
 
 #include <cerrno>
 #include <cstring>
@@ -36,12 +40,22 @@ along with this program.  If not, see <http://www.gnu.
 #include <signal.h>
 #include <sys/mman.h>
 #include <sys/param.h>
+#include <sys/types.h>
 #include <sys/ptrace.h>
 #include <sys/sysctl.h>
 #include <sys/user.h>
 #include <sys/wait.h>
 #include <unistd.h>
+#include <Posix.h>
 
+#include <sys/syscall.h> /* For SYS_xxx definitions */
+#include <Status.h>
+#include <Configuration.h>
+#include <Unix.h>
+#include <util/String.h>
+#include <Status.h>
+#include <sys/wait.h>
+
 namespace DebuggerCorePlugin {
 
 namespace {
@@ -62,6 +76,21 @@ int resume_code(int status) {
 }
 }
 
+/**
+ * @brief disable_aslr
+ */
+void disable_aslr() {
+}
+
+/**
+ * @brief disable_lazy_binding
+ */
+void disable_lazy_binding() {
+	if (setenv("LD_BIND_NOW", "1", true) == -1) {
+		perror("Failed to disable lazy binding");
+	}
+}
+
 //------------------------------------------------------------------------------
 // Name: DebuggerCore
 // Desc: constructor
@@ -80,7 +109,7 @@ DebuggerCore::DebuggerCore() {
 // Name:
 // Desc:
 //------------------------------------------------------------------------------
-bool DebuggerCore::has_extension(quint64 ext) const {
+bool DebuggerCore::hasExtension(uint64_t ext) const {
 	Q_UNUSED(ext)
 	return false;
 }
@@ -89,10 +118,18 @@ bool DebuggerCore::has_extension(quint64 ext) const {
 // Name: page_size
 // Desc: returns the size of a page on this system
 //------------------------------------------------------------------------------
-size_t DebuggerCore::page_size() const {
+size_t DebuggerCore::pageSize() const {
 	return page_size_;
 }
 
+/**
+ * @brief DebuggerCore::pointerSize
+ * @return
+ */
+std::size_t DebuggerCore::pointerSize() const {
+	return pointerSize_;
+}
+
 //------------------------------------------------------------------------------
 // Name: ~DebuggerCore
 // Desc:
@@ -101,59 +138,39 @@ DebuggerCore::~DebuggerCore() {
 	detach();
 }
 
-//------------------------------------------------------------------------------
-// Name: wait_debug_event
-// Desc: waits for a debug event, msecs is a timeout
-//      it will return false if an error or timeout occurs
-//------------------------------------------------------------------------------
-std::shared_ptr<const IDebugEvent> DebuggerCore::wait_debug_event(int msecs) {
-	if (attached()) {
-		int status;
-		bool timeout;
+/**
+ * waits for a debug event, witha timeout specified in milliseconds
+ *
+ * @brief DebuggerCore::waitDebugEvent
+ * @param msecs
+ * @return nullptr if an error or timeout occurs
+ */
+std::shared_ptr<IDebugEvent> DebuggerCore::waitDebugEvent(std::chrono::milliseconds msecs) {
 
-		const edb::tid_t tid = Posix::waitpid_timeout(pid(), &status, 0, msecs, &timeout);
-		if (!timeout) {
-			if (tid > 0) {
-
-				// normal event
-				auto e    = std::make_shared<PlatformEvent>();
-				e->pid    = pid();
-				e->tid    = tid;
-				e->status = status;
-
-				char errbuf[_POSIX2_LINE_MAX];
-				if (kvm_t *const kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf)) {
-					int rc;
-					struct kinfo_proc *const proc = kvm_getprocs(kd, KERN_PROC_PID, pid(), &rc);
-
-					struct proc p;
-					kvm_read(kd, (unsigned long)proc->ki_paddr, &p, sizeof(p));
-
-					struct ksiginfo siginfo;
-					kvm_read(kd, (unsigned long)p.p_ksi, &siginfo, sizeof(siginfo));
-
-					// TODO: why doesn't this get the fault address correctly?
-					// perhaps I need to target the tid instead?
-					e->fault_code_    = siginfo.ksi_code;
-					e->fault_address_ = siginfo.ksi_addr;
-
-					//printf("ps_sig   : %d\n", siginfo.ksi_signo);
-					//printf("ps_type  : %d\n", p.p_stype);
-					kvm_close(kd);
-				} else {
-					e->fault_code_    = 0;
-					e->fault_address_ = 0;
-				}
-
-				active_thread_       = tid;
-				threads_[tid].status = status;
-				return e;
+	if (process_) {
+		if (!Posix::wait_for_sigchld(msecs)) {
+			for (auto &thread : process_->threads()) {
+				int status;
+				//const edb::tid_t tid = Posix::waitpid(thread->tid(), &status, __WALL | WNOHANG);
+				//if (tid > 0) {
+				//	return handleEvent(tid, status);
+				//}
 			}
 		}
 	}
 	return nullptr;
 }
 
+/**
+ * @brief DebuggerCore::handleEvent
+ * @param tid
+ * @param status
+ * @return
+ */
+std::shared_ptr<IDebugEvent> DebuggerCore::handleEvent(edb::tid_t tid, int status) {
+	return nullptr;
+}
+
 //------------------------------------------------------------------------------
 // Name: read_data
 // Desc:
@@ -162,7 +179,8 @@ long DebuggerCore::read_data(edb::address_t address, b
 
 	Q_ASSERT(ok);
 	errno        = 0;
-	const long v = ptrace(PT_READ_D, pid(), reinterpret_cast<char *>(address), 0);
+	//const long v = ptrace(PT_READ_D, getpid(), reinterpret_cast<char *>(address), 0);
+	const long v =' ';
 	SET_OK(*ok, v);
 	return v;
 }
@@ -172,60 +190,131 @@ long DebuggerCore::read_data(edb::address_t address, b
 // Desc:
 //------------------------------------------------------------------------------
 bool DebuggerCore::write_data(edb::address_t address, long value) {
-	return ptrace(PT_WRITE_D, pid(), reinterpret_cast<char *>(address), value) != -1;
+	//return ptrace(PT_WRITE_D, pid(), reinterpret_cast<char *>(address), value) != -1;
+	return false;
 }
 
-//------------------------------------------------------------------------------
-// Name: attach
-// Desc:
-//------------------------------------------------------------------------------
-bool DebuggerCore::attach(edb::pid_t pid) {
-	detach();
+/**
+ * @brief DebuggerCore::attach
+ * @param pid
+ * @return
+ */
+Status DebuggerCore::attach(edb::pid_t pid) {
 
-	const long ret = ptrace(PT_ATTACH, pid, 0, 0);
-	if (ret == 0) {
-		pid_           = pid;
-		active_thread_ = pid;
-		threads_.clear();
-		threads_.insert(pid, thread_info());
+	endDebugSession();
+	int lastErr = 0;
+	process_ = nullptr;
+	return Status(std::strerror(lastErr));
+}
 
-		// TODO: attach to all of the threads
+/**
+ * @brief DebuggerCore::detach
+ * @return
+ */
+Status DebuggerCore::detach() {
+
+	QString errorMessage;
+
+	if (errorMessage.isEmpty()) {
+		return Status::Ok;
 	}
 
-	return ret == 0;
+	qWarning() << errorMessage.toStdString().c_str();
+	return Status(errorMessage);
 }
 
-//------------------------------------------------------------------------------
-// Name: detach
-// Desc:
-//------------------------------------------------------------------------------
-void DebuggerCore::detach() {
+/**
+ * @brief DebuggerCore::kill
+ */
+void DebuggerCore::kill() {
 	if (attached()) {
+		clearBreakpoints();
 
-		// TODO: do i need to stop each thread first, and wait for them?
+		::kill(process_->pid(), SIGKILL);
 
-		clear_breakpoints();
-		for (auto it = threads_.begin(); it != threads_.end(); ++it) {
-			ptrace(PT_DETACH, it.key(), 0, 0);
-		}
+		pid_t ret;
+		//while ((ret = Posix::waitpid(-1, nullptr, __WALL)) != process_->pid() && ret != -1)
+			;
 
-		pid_ = 0;
-		threads_.clear();
+		process_ = nullptr;
+		reset();
 	}
 }
 
-//------------------------------------------------------------------------------
-// Name: kill
-// Desc:
-//------------------------------------------------------------------------------
-void DebuggerCore::kill() {
-	if (attached()) {
-		clear_breakpoints();
-		ptrace(PT_KILL, pid(), 0, 0);
-		Posix::waitpid(pid(), 0, WAIT_ANY);
-		pid_ = 0;
-		threads_.clear();
+/**
+ * @brief DebuggerCore::lastMeansOfCapture
+ * @return how the last process was captured to debug
+ */
+DebuggerCore::MeansOfCapture DebuggerCore::lastMeansOfCapture() const {
+	return MeansOfCapture::NeverCaptured;
+}
+
+/**
+ * @brief DebuggerCore::reset
+ */
+void DebuggerCore::reset() {
+	threads_.clear();
+	waitedThreads_.clear();
+	activeThread_ = 0;
+}
+
+
+/**
+ * @brief DebuggerCore::detectCpuMode
+ */
+void DebuggerCore::detectCpuMode() {
+
+#if defined(EDB_X86) || defined(EDB_X86_64)
+
+#if defined(EDB_X86)
+	constexpr size_t Offset = offsetof(UserRegsStructX86, xcs);
+#elif defined(EDB_X86_64)
+//	constexpr size_t Offset = offsetof(UserRegsStructX86_64, cs);
+#endif
+
+	errno                   = 0;
+//	const edb::seg_reg_t cs = ptrace(PTRACE_PEEKUSER, activeThread_, Offset, 0);
+
+	if (!errno) {
+//		if (cs == userCodeSegment32_) {
+//			if (pointerSize_ == sizeof(uint64_t)) {
+//				qDebug() << "Debuggee is now 32 bit";
+//				cpuMode_ = CpuMode::x86_32;
+//				CapstoneEDB::init(CapstoneEDB::Architecture::ARCH_X86);
+//			}
+//			pointerSize_ = sizeof(uint32_t);
+//			return;
+//		} else if (cs == userCodeSegment64_) {
+//			if (pointerSize_ == sizeof(uint32_t)) {
+//				qDebug() << "Debuggee is now 64 bit";
+//				cpuMode_ = CpuMode::x86_64;
+//				CapstoneEDB::init(CapstoneEDB::Architecture::ARCH_AMD64);
+//			}
+//			pointerSize_ = sizeof(uint64_t);
+//			return;
+//		}
 	}
+#elif defined(EDB_ARM32)
+	errno           = 0;
+	const auto cpsr = ptrace(PTRACE_PEEKUSER, activeThread_, sizeof(long) * 16, 0L);
+	if (!errno) {
+		const bool thumb = cpsr & 0x20;
+		if (thumb) {
+			cpuMode_ = CpuMode::Thumb;
+			CapstoneEDB::init(CapstoneEDB::Architecture::ARCH_ARM32_THUMB);
+		} else {
+			cpuMode_ = CpuMode::ARM32;
+			CapstoneEDB::init(CapstoneEDB::Architecture::ARCH_ARM32_ARM);
+		}
+	}
+	pointerSize_ = sizeof(uint32_t);
+#elif defined(EDB_ARM64)
+	cpuMode_ = CpuMode::ARM64;
+	CapstoneEDB::init(CapstoneEDB::Architecture::ARCH_ARM64);
+	pointerSize_ = sizeof(uint64_t);
+#else
+#error "Unsupported Architecture"
+#endif
 }
 
 //------------------------------------------------------------------------------
@@ -241,124 +330,145 @@ void DebuggerCore::pause() {
 }
 
 //------------------------------------------------------------------------------
-// Name: resume
+// Name: open
 // Desc:
 //------------------------------------------------------------------------------
-void DebuggerCore::resume(edb::EVENT_STATUS status) {
-	// TODO: assert that we are paused
+Status DebuggerCore::open(const QString &path, const QString &cwd, const QList<QByteArray> &args, const QString &input, const QString &output) {
+	endDebugSession();
 
-	if (attached()) {
-		if (status != edb::DEBUG_STOP) {
-			const edb::tid_t tid = active_thread();
-			const int code       = (status == edb::DEBUG_EXCEPTION_NOT_HANDLED) ? resume_code(threads_[tid].status) : 0;
-			ptrace(PT_CONTINUE, tid, reinterpret_cast<caddr_t>(1), code);
-		}
-	}
-}
+	constexpr std::size_t SharedMemSize = 4096;
 
-//------------------------------------------------------------------------------
-// Name: open
-// Desc:
-//------------------------------------------------------------------------------
-bool DebuggerCore::open(const QString &path, const QString &cwd, const QList<QByteArray> &args, const QString &tty) {
-	detach();
-	pid_t pid;
+	void *const ptr      = ::mmap(nullptr, SharedMemSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
+	const auto sharedMem = static_cast<QChar *>(ptr);
 
-	switch (pid = fork()) {
+	std::memset(ptr, 0, SharedMemSize);
+
+	switch (pid_t pid = fork()) {
 	case 0:
+	{
 		// we are in the child now...
 
 		// set ourselves (the child proc) up to be traced
 		ptrace(PT_TRACE_ME, 0, 0, 0);
 
 		// redirect it's I/O
-		if (!tty.isEmpty()) {
-			FILE *const std_out = freopen(qPrintable(tty), "r+b", stdout);
-			FILE *const std_in  = freopen(qPrintable(tty), "r+b", stdin);
-			FILE *const std_err = freopen(qPrintable(tty), "r+b", stderr);
+		FILE *std_in  = nullptr;
+		FILE *std_out = nullptr;
+		FILE *std_err = nullptr;
 
-			Q_UNUSED(std_out)
-			Q_UNUSED(std_in)
-			Q_UNUSED(std_err)
+		if (!input.isEmpty()) {
+			std_in = freopen(qPrintable(input), "rb", stdin);
 		}
 
+		if (!output.isEmpty()) {
+			std_out = freopen(qPrintable(output), "wb", stdout);
+			std_err = freopen(qPrintable(output), "wb", stderr);
+		}
+
+		Q_UNUSED(std_in)
+		Q_UNUSED(std_out)
+		Q_UNUSED(std_err)
+
+		if (edb::v1::config().disableASLR) {
+			disable_aslr();
+		}
+
+		if (edb::v1::config().disableLazyBinding) {
+			disable_lazy_binding();
+		}
+
 		// do the actual exec
-		execute_process(path, cwd, args);
+		const Status status = Unix::execute_process(path, cwd, args);
 
+		static_assert(std::is_trivially_copyable<QChar>::value, "Can't copy string of QChar to shared memory");
+
+		QString error = status.error();
+		std::memcpy(sharedMem, error.constData(), std::min(sizeof(QChar) * error.size(), SharedMemSize - sizeof(QChar) /*prevent overwriting of last null*/));
+
 		// we should never get here!
 		abort();
 		break;
+	}
 	case -1:
-		// error!
-		pid_ = 0;
-		return false;
+		// error! for some reason we couldn't fork
+		reset();
+		return Status(tr("Failed to fork"));
 	default:
 		// parent
 		do {
 			threads_.clear();
 
 			int status;
-			if (Posix::waitpid(pid, &status, 0) == -1) {
-				return false;
+//			const auto wpidRet = Posix::waitpid(pid, &status, __WALL);
+			const QString childError(sharedMem);
+			::munmap(sharedMem, SharedMemSize);
+//			if (wpidRet == -1) {
+//				return Status(tr("waitpid() failed: %1").arg(std::strerror(errno)) + (childError.isEmpty() ? "" : tr(".\nError returned by child:\n%1.").arg(childError)));
+//			}
+
+			if (WIFEXITED(status)) {
+				return Status(tr("The child unexpectedly exited with code %1. Error returned by child:\n%2").arg(WEXITSTATUS(status)).arg(childError));
 			}
 
+			if (WIFSIGNALED(status)) {
+				return Status(tr("The child was unexpectedly killed by signal %1. Error returned by child:\n%2").arg(WTERMSIG(status)).arg(childError));
+			}
+
+			// This happens when exec failed, but just in case it's something another return some description.
+			if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGABRT) {
+				return Status(childError.isEmpty() ? tr("The child unexpectedly aborted") : childError);
+			}
+
 			// the very first event should be a STOP of type SIGTRAP
 			if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
-				detach();
-				return false;
+				endDebugSession();
+				return Status(tr("First event after waitpid() should be a STOP of type SIGTRAP, but wasn't, instead status=0x%1")
+								  .arg(status, 0, 16) +
+							  (childError.isEmpty() ? "" : tr(".\nError returned by child:\n%1.").arg(childError)));
 			}
 
 			// setup the first event data for the primary thread
-			threads_.insert(pid, thread_info());
-			pid_                 = pid;
-			active_thread_       = pid;
-			threads_[pid].status = status;
-			return true;
+//			threads_.insert(pid, thread_info());
+//			pid_                 = pid;
+//			active_thread_       = pid;
+//			threads_[pid].status = status;
+			return Status::Ok;
 		} while (0);
 		break;
 	}
 }
 
-//------------------------------------------------------------------------------
-// Name: set_active_thread
-// Desc:
-//------------------------------------------------------------------------------
-void DebuggerCore::set_active_thread(edb::tid_t tid) {
-	Q_ASSERT(threads_.contains(tid));
-	active_thread_ = tid;
-}
 
-//------------------------------------------------------------------------------
-// Name: create_state
-// Desc:
-//------------------------------------------------------------------------------
-std::unique_ptr<IState> DebuggerCore::create_state() const {
-	return std::make_unique<PlatformState>();
+/**
+ * @brief DebuggerCore::createState
+ * @return
+ */
+std::unique_ptr<IState> DebuggerCore::createState() const {
+//	return std::make_unique<PlatformState>();
+	return nullptr;
 }
 
-//------------------------------------------------------------------------------
-// Name: enumerate_processes
-// Desc:
-//------------------------------------------------------------------------------
-QMap<edb::pid_t, ProcessInfo> DebuggerCore::enumerate_processes() const {
-	QMap<edb::pid_t, ProcessInfo> ret;
+/**
+ * @brief DebuggerCore::enumerateProcesses
+ * @return
+ */
+QMap<edb::pid_t, std::shared_ptr<IProcess>> DebuggerCore::enumerateProcesses() const {
+	QMap<edb::pid_t, std::shared_ptr<IProcess>> ret;
 
-	char ebuffer[_POSIX2_LINE_MAX];
-	int numprocs;
-	if (kvm_t *const kaccess = kvm_openfiles(_PATH_DEVNULL, _PATH_DEVNULL, 0, O_RDONLY, ebuffer)) {
-		if (struct kinfo_proc *const kprocaccess = kvm_getprocs(kaccess, KERN_PROC_ALL, 0, &numprocs)) {
-			for (int i = 0; i < numprocs; ++i) {
-				ProcessInfo procInfo;
+	QDir proc_directory("/proc/");
+	QFileInfoList entries = proc_directory.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
 
-				procInfo.pid  = kprocaccess[i].ki_pid;
-				procInfo.uid  = kprocaccess[i].ki_uid;
-				procInfo.name = kprocaccess[i].ki_comm;
-				ret.insert(procInfo.pid, procInfo);
-			}
+	for (const QFileInfo &info : entries) {
+		const QString filename = info.fileName();
+		if (util::is_numeric(filename)) {
+			const edb::pid_t pid = filename.toInt();
+
+			// NOTE(eteran): the const_cast is reasonable here.
+			// While we don't want THIS function to mutate the DebuggerCore object
+			// we do want the associated PlatformProcess to be able to trigger
+			// non-const operations in the future, at least hypothetically.
+//			ret.insert(pid, std::make_shared<PlatformProcess>(const_cast<DebuggerCore *>(this), pid));
 		}
-		kvm_close(kaccess);
-	} else {
-		QMessageBox::warning(0, "Error Listing Processes", ebuffer);
 	}
 
 	return ret;
@@ -368,42 +478,44 @@ QMap<edb::pid_t, ProcessInfo> DebuggerCore::enumerate_
 // Name:
 // Desc:
 //------------------------------------------------------------------------------
-edb::pid_t DebuggerCore::parent_pid(edb::pid_t pid) const {
+edb::pid_t DebuggerCore::parentPid(edb::pid_t pid) const {
 	// TODO: implement this
 	return -1;
 }
 
-//------------------------------------------------------------------------------
-// Name:
-// Desc:
-//------------------------------------------------------------------------------
-quint64 DebuggerCore::cpu_type() const {
-#ifdef EDB_X86
-	return edb::string_hash<'x', '8', '6'>::value;
-#elif defined(EDB_X86_64)
-	return edb::string_hash<'x', '8', '6', '-', '6', '4'>::value;
+/**
+ * @brief DebuggerCore::cpuType
+ * @return edb's native CPU type
+ */
+uint64_t DebuggerCore::cpuType() const {
+#if defined(EDB_X86_64)
+	return edb::string_hash("x86-64");
+#elif defined(EDB_X86)
+	return edb::string_hash("x86");
+#elif defined(EDB_ARM32)
+	return edb::string_hash("arm");
+#elif defined(EDB_ARM64)
+	return edb::string_hash("AArch64");
+#else
+#error "Unsupported Architecture"
 #endif
 }
 
-//------------------------------------------------------------------------------
-// Name:
-// Desc:
-//------------------------------------------------------------------------------
-QString DebuggerCore::format_pointer(edb::address_t address) const {
-	char buf[32];
-#ifdef EDB_X86
-	qsnprintf(buf, sizeof(buf), "%08x", address);
-#elif defined(EDB_X86_64)
-	qsnprintf(buf, sizeof(buf), "%016llx", address);
-#endif
-	return buf;
+
+/**
+ * @brief DebuggerCore::setIgnoredExceptions
+ * @param exceptions
+ */
+void DebuggerCore::setIgnoredExceptions(const QList<qlonglong> &exceptions) {
+
 }
 
+
 //------------------------------------------------------------------------------
 // Name:
 // Desc:
 //------------------------------------------------------------------------------
-QString DebuggerCore::stack_pointer() const {
+QString DebuggerCore::stackPointer() const {
 #ifdef EDB_X86
 	return "esp";
 #elif defined(EDB_X86_64)
@@ -411,15 +523,21 @@ QString DebuggerCore::stack_pointer() const {
 #endif
 }
 
-//------------------------------------------------------------------------------
-// Name:
-// Desc:
-//------------------------------------------------------------------------------
-QString DebuggerCore::frame_pointer() const {
-#ifdef EDB_X86
-	return "ebp";
-#elif defined(EDB_X86_64)
-	return "rbp";
+/**
+ * @brief DebuggerCore::framePointer
+ * @return
+ */
+QString DebuggerCore::framePointer() const {
+#if defined(EDB_X86) || defined(EDB_X86_64)
+	if (edb::v1::debuggeeIs32Bit()) {
+		return "ebp";
+	} else {
+		return "rbp";
+	}
+#elif defined(EDB_ARM32) || defined(EDB_ARM64)
+	return "fp";
+#else
+#error "Unsupported Architecture"
 #endif
 }
 
@@ -427,11 +545,78 @@ QString DebuggerCore::frame_pointer() const {
 // Name:
 // Desc:
 //------------------------------------------------------------------------------
-QString DebuggerCore::instruction_pointer() const {
+QString DebuggerCore::instructionPointer() const {
 #ifdef EDB_X86
 	return "eip";
 #elif defined(EDB_X86_64)
 	return "rip";
+#endif
+}
+
+/**
+ * @brief DebuggerCore::flagRegister
+ * @return the name of the flag register
+ */
+QString DebuggerCore::flagRegister() const {
+#if defined(EDB_X86) || defined(EDB_X86_64)
+	if (edb::v1::debuggeeIs32Bit()) {
+		return "eflags";
+	} else {
+		return "rflags";
+	}
+#elif defined(EDB_ARM32) || defined(EDB_ARM64)
+	return "cpsr";
+#else
+#error "Unsupported Architecture"
+#endif
+}
+
+/**
+ * @brief DebuggerCore::process
+ * @return
+ */
+IProcess *DebuggerCore::process() const {
+	return process_.get();
+}
+
+/**
+ * @brief DebuggerCore::exceptions
+ * @return
+ */
+QMap<qlonglong, QString> DebuggerCore::exceptions() const {
+	return Unix::exceptions();
+}
+
+/**
+ * @brief DebuggerCore::exceptionName
+ * @param value
+ * @return
+ */
+QString DebuggerCore::exceptionName(qlonglong value) {
+	return Unix::exception_name(value);
+}
+
+/**
+ * @brief DebuggerCore::exceptionValue
+ * @param name
+ * @return
+ */
+qlonglong DebuggerCore::exceptionValue(const QString &name) {
+	return Unix::exception_value(name);
+}
+
+/**
+ * @brief DebuggerCore::nopFillByte
+ * @return
+ */
+uint8_t DebuggerCore::nopFillByte() const {
+#if defined(EDB_X86) || defined(EDB_X86_64)
+	return 0x90;
+#elif defined(EDB_ARM32) || defined(EDB_ARM64)
+	// TODO(eteran): does this concept even make sense for a multi-byte instruction encoding?
+	return 0x00;
+#else
+#error "Unsupported Architecture"
 #endif
 }
 

--- plugins/DebuggerCore/unix/freebsd/PlatformEvent.cpp.orig	2020-12-14 01:01:38 UTC
+++ plugins/DebuggerCore/unix/freebsd/PlatformEvent.cpp
@@ -51,73 +51,252 @@ PlatformEvent *PlatformEvent::clone() const {
 	return new PlatformEvent(*this);
 }
 
+/**
+ * @brief PlatformEvent::createUnexpectedSignalMessage
+ * @param name
+ * @param number
+ * @return
+ */
+IDebugEvent::Message PlatformEvent::createUnexpectedSignalMessage(const QString &name, int number) {
+	return Message(
+		tr("Unexpected Signal Encountered"),
+		tr("<p>The debugged application encountered a %1 (%2).</p>").arg(name).arg(number),
+		tr("% received").arg(name));
+}
+
 //------------------------------------------------------------------------------
 // Name:
 //------------------------------------------------------------------------------
-IDebugEvent::Message PlatformEvent::error_description() const {
-	Q_ASSERT(is_error());
+IDebugEvent::Message PlatformEvent::errorDescription() const {
+	Q_ASSERT(isError());
 
-	auto fault_address = reinterpret_cast<edb::address_t>(fault_address_);
+	auto fault_address = edb::address_t::fromZeroExtended(siginfo_.si_addr);
 
+	std::size_t debuggeePtrSize = edb::v1::pointer_size();
+	bool fullAddressKnown       = debuggeePtrSize <= sizeof(void *);
+	const QString addressString = fault_address.toPointerString(fullAddressKnown);
+
+		Message message;
 	switch (code()) {
 	case SIGSEGV:
-		return Message(
-			tr("Illegal Access Fault"),
-			tr(
-				"<p>The debugged application encountered a segmentation fault.<br />The address <strong>0x%1</strong> could not be accessed.</p>"
-				"<p>If you would like to pass this exception to the application press Shift+[F7/F8/F9]</p>")
-				.arg(edb::v1::format_pointer(fault_address)));
+		switch (siginfo_.si_code) {
+		case SEGV_MAPERR:
+			message = Message(
+				tr("Illegal Access Fault"),
+				tr("<p>The debugged application encountered a segmentation fault.<br />The address <strong>%1</strong> does not appear to be mapped.</p>").arg(addressString),
+				tr("SIGSEGV: SEGV_MAPERR: Accessed address %1 not mapped").arg(addressString));
+			break;
+		case SEGV_ACCERR:
+			message = Message(
+				tr("Illegal Access Fault"),
+				tr("<p>The debugged application encountered a segmentation fault.<br />The address <strong>%1</strong> could not be accessed.</p>").arg(addressString),
+				tr("SIGSEGV: SEGV_ACCERR: Access to address %1 not permitted").arg(addressString));
+			break;
+		default:
+			message = Message(
+				tr("Illegal Access Fault"),
+				tr("<p>The debugged application encountered a segmentation fault.<br />The instruction could not be executed.</p>"),
+				tr("SIGSEGV: Segmentation fault"));
+			break;
+		}
+		break;
+
 	case SIGILL:
-		return Message(
+		message = Message(
 			tr("Illegal Instruction Fault"),
-			tr(
-				"<p>The debugged application attempted to execute an illegal instruction.</p>"
-				"<p>If you would like to pass this exception to the application press Shift+[F7/F8/F9]</p>"));
+			tr("<p>The debugged application attempted to execute an illegal instruction.</p>"),
+			tr("SIGILL: Illegal instruction"));
+		break;
 	case SIGFPE:
-		switch (fault_code_) {
+		switch (siginfo_.si_code) {
 		case FPE_INTDIV:
-			return Message(
+			message = Message(
 				tr("Divide By Zero"),
-				tr(
-					"<p>The debugged application tried to divide an integer value by an integer divisor of zero.</p>"
-					"<p>If you would like to pass this exception to the application press Shift+[F7/F8/F9]</p>"));
+				tr("<p>The debugged application tried to divide an integer value by an integer divisor of zero or encountered integer division overflow.</p>"),
+				tr("SIGFPE: FPE_INTDIV: Integer division by zero or division overflow"));
+			break;
+		case FPE_FLTDIV:
+			message = Message(
+				tr("Divide By Zero"),
+				tr("<p>The debugged application tried to divide an floating-point value by a floating-point divisor of zero.</p>"),
+				tr("SIGFPE: FPE_FLTDIV: Floating-point division by zero"));
+			break;
+		case FPE_FLTOVF:
+			message = Message(
+				tr("Numeric Overflow"),
+				tr("<p>The debugged application encountered a numeric overflow while performing a floating-point computation.</p>"),
+				tr("SIGFPE: FPE_FLTOVF: Numeric overflow exception"));
+			break;
+		case FPE_FLTUND:
+			message = Message(
+				tr("Numeric Underflow"),
+				tr("<p>The debugged application encountered a numeric underflow while performing a floating-point computation.</p>"),
+				tr("SIGFPE: FPE_FLTUND: Numeric underflow exception"));
+			break;
+		case FPE_FLTRES:
+			message = Message(
+				tr("Inexact Result"),
+				tr("<p>The debugged application encountered an inexact result of a floating-point computation it was performing.</p>"),
+				tr("SIGFPE: FPE_FLTRES: Inexact result exception"));
+			break;
+		case FPE_FLTINV:
+			message = Message(
+				tr("Invalid Operation"),
+				tr("<p>The debugged application attempted to perform an invalid floating-point operation.</p>"),
+				tr("SIGFPE: FPE_FLTINV: Invalid floating-point operation"));
+			break;
 		default:
-			return Message(
+			message = Message(
 				tr("Floating Point Exception"),
-				tr(
-					"<p>The debugged application encountered a floating-point exception.</p>"
-					"<p>If you would like to pass this exception to the application press Shift+[F7/F8/F9]</p>"));
+				tr("<p>The debugged application encountered a floating-point exception.</p>"),
+				tr("SIGFPE: Floating-point exception"));
+			break;
 		}
+		break;
 
 	case SIGABRT:
-		return Message(
+		message = Message(
 			tr("Application Aborted"),
-			tr(
-				"<p>The debugged application has aborted.</p>"
-				"<p>If you would like to pass this exception to the application press Shift+[F7/F8/F9]</p>"));
+			tr("<p>The debugged application has aborted.</p>"),
+			tr("SIGABRT: Application aborted"));
+		break;
 	case SIGBUS:
-		return Message(
+		message = Message(
 			tr("Bus Error"),
-			tr(
-				"<p>The debugged application tried to read or write data that is misaligned.</p>"
-				"<p>If you would like to pass this exception to the application press Shift+[F7/F8/F9]</p>"));
+			tr("<p>The debugged application received a bus error. Typically, this means that it tried to read or write data that is misaligned.</p>"),
+			tr("SIGBUS: Bus error"));
+		break;
 #ifdef SIGSTKFLT
 	case SIGSTKFLT:
-		return Message(
+		message = Message(
 			tr("Stack Fault"),
-			tr(
-				"<p>The debugged application encountered a stack fault.</p>"
-				"<p>If you would like to pass this exception to the application press Shift+[F7/F8/F9]</p>"));
+			tr("<p>The debugged application encountered a stack fault.</p>"),
+			tr("SIGSTKFLT: Stack fault"));
+		break;
 #endif
 	case SIGPIPE:
-		return Message(
+		message = Message(
 			tr("Broken Pipe Fault"),
-			tr(
-				"<p>The debugged application encountered a broken pipe fault.</p>"
-				"<p>If you would like to pass this exception to the application press Shift+[F7/F8/F9]</p>"));
+			tr("<p>The debugged application encountered a broken pipe fault.</p>"),
+			tr("SIGPIPE: Pipe broken"));
+		break;
+#ifdef SIGHUP
+	case SIGHUP:
+		message = createUnexpectedSignalMessage("SIGHUP", SIGHUP);
+		break;
+#endif
+#ifdef SIGINT
+	case SIGINT:
+		message = createUnexpectedSignalMessage("SIGINT", SIGINT);
+		break;
+#endif
+#ifdef SIGQUIT
+	case SIGQUIT:
+		message = createUnexpectedSignalMessage("SIGQUIT", SIGQUIT);
+		break;
+#endif
+#ifdef SIGTRAP
+	case SIGTRAP:
+		message = createUnexpectedSignalMessage("SIGTRAP", SIGTRAP);
+		break;
+#endif
+#ifdef SIGKILL
+	case SIGKILL:
+		message = createUnexpectedSignalMessage("SIGKILL", SIGKILL);
+		break;
+#endif
+#ifdef SIGUSR1
+	case SIGUSR1:
+		message = createUnexpectedSignalMessage("SIGUSR1", SIGUSR1);
+		break;
+#endif
+#ifdef SIGUSR2
+	case SIGUSR2:
+		message = createUnexpectedSignalMessage("SIGUSR2", SIGUSR2);
+		break;
+#endif
+#ifdef SIGALRM
+	case SIGALRM:
+		message = createUnexpectedSignalMessage("SIGALRM", SIGALRM);
+		break;
+#endif
+#ifdef SIGTERM
+	case SIGTERM:
+		message = createUnexpectedSignalMessage("SIGTERM", SIGTERM);
+		break;
+#endif
+#ifdef SIGCHLD
+	case SIGCHLD:
+		message = createUnexpectedSignalMessage("SIGCHLD", SIGCHLD);
+		break;
+#endif
+#ifdef SIGCONT
+	case SIGCONT:
+		message = createUnexpectedSignalMessage("SIGCONT", SIGCONT);
+		break;
+#endif
+#ifdef SIGSTOP
+	case SIGSTOP:
+		message = createUnexpectedSignalMessage("SIGSTOP", SIGSTOP);
+		break;
+#endif
+#ifdef SIGTSTP
+	case SIGTSTP:
+		message = createUnexpectedSignalMessage("SIGTSTP", SIGTSTP);
+		break;
+#endif
+#ifdef SIGTTIN
+	case SIGTTIN:
+		message = createUnexpectedSignalMessage("SIGTTIN", SIGTTIN);
+		break;
+#endif
+#ifdef SIGTTOU
+	case SIGTTOU:
+		message = createUnexpectedSignalMessage("SIGTTOU", SIGTTOU);
+		break;
+#endif
+#ifdef SIGURG
+	case SIGURG:
+		message = createUnexpectedSignalMessage("SIGURG", SIGURG);
+		break;
+#endif
+#ifdef SIGXCPU
+	case SIGXCPU:
+		message = createUnexpectedSignalMessage("SIGXCPU", SIGXCPU);
+		break;
+#endif
+#ifdef SIGXFSZ
+	case SIGXFSZ:
+		message = createUnexpectedSignalMessage("SIGXFSZ", SIGXFSZ);
+		break;
+#endif
+#ifdef SIGVTALRM
+	case SIGVTALRM:
+		message = createUnexpectedSignalMessage("SIGVTALRM", SIGVTALRM);
+		break;
+#endif
+#ifdef SIGPROF
+	case SIGPROF:
+		message = createUnexpectedSignalMessage("SIGPROF", SIGPROF);
+		break;
+#endif
+#ifdef SIGWINCH
+	case SIGWINCH:
+		message = createUnexpectedSignalMessage("SIGWINCH", SIGWINCH);
+		break;
+#endif
+#ifdef SIGIO
+	case SIGIO:
+		message = createUnexpectedSignalMessage("SIGIO", SIGIO);
+		break;
+#endif
 	default:
 		return Message();
 	}
+
+	message.message += "<p>If you would like to pass this exception to the application press Shift+[F7/F8/F9]</p>";
+	message.statusMessage += ". Shift+Run/Step to pass signal to the program";
+	return message;
 }
 
 //------------------------------------------------------------------------------
@@ -140,7 +319,7 @@ IDebugEvent::REASON PlatformEvent::reason() const {
 //------------------------------------------------------------------------------
 // Name:
 //------------------------------------------------------------------------------
-IDebugEvent::TRAP_REASON PlatformEvent::trap_reason() const {
+IDebugEvent::TRAP_REASON PlatformEvent::trapReason() const {
 	switch (fault_code_) {
 	case TRAP_TRACE:
 		return TRAP_STEPPING;
@@ -159,7 +338,7 @@ bool PlatformEvent::exited() const {
 //------------------------------------------------------------------------------
 // Name:
 //------------------------------------------------------------------------------
-bool PlatformEvent::is_error() const {
+bool PlatformEvent::isError() const {
 	if (stopped()) {
 		switch (code()) {
 		case SIGTRAP:
@@ -186,21 +365,21 @@ bool PlatformEvent::is_error() const {
 //------------------------------------------------------------------------------
 // Name:
 //------------------------------------------------------------------------------
-bool PlatformEvent::is_kill() const {
+bool PlatformEvent::isKill() const {
 	return stopped() && code() == SIGKILL;
 }
 
 //------------------------------------------------------------------------------
 // Name:
 //------------------------------------------------------------------------------
-bool PlatformEvent::is_stop() const {
+bool PlatformEvent::isStop() const {
 	return stopped() && code() == SIGSTOP;
 }
 
 //------------------------------------------------------------------------------
 // Name:
 //------------------------------------------------------------------------------
-bool PlatformEvent::is_trap() const {
+bool PlatformEvent::isTrap() const {
 	return stopped() && code() == SIGTRAP;
 }
 

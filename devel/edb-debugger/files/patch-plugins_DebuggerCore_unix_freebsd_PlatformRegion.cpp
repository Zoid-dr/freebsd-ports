--- plugins/DebuggerCore/unix/freebsd/PlatformRegion.cpp.orig	2020-12-14 01:01:38 UTC
+++ plugins/DebuggerCore/unix/freebsd/PlatformRegion.cpp
@@ -57,7 +57,7 @@ size_t PlatformRegion::size() const {
 	return end_ - start_;
 }
 
-void PlatformRegion::set_permissions(bool read, bool write, bool execute) {
+void PlatformRegion::setPermissions(bool read, bool write, bool execute) {
 	Q_UNUSED(read)
 	Q_UNUSED(write)
 	Q_UNUSED(execute)
@@ -83,11 +83,11 @@ IRegion::permissions_t PlatformRegion::permissions() c
 	return permissions_;
 }
 
-void PlatformRegion::set_start(edb::address_t address) {
+void PlatformRegion::setStart(edb::address_t address) {
 	start_ = address;
 }
 
-void PlatformRegion::set_end(edb::address_t address) {
+void PlatformRegion::setEnd(edb::address_t address) {
 	end_ = address;
 }
 

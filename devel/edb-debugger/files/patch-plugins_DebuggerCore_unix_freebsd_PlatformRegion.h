--- plugins/DebuggerCore/unix/freebsd/PlatformRegion.h.orig	2020-12-14 01:01:38 UTC
+++ plugins/DebuggerCore/unix/freebsd/PlatformRegion.h
@@ -43,9 +43,9 @@ class PlatformRegion : public IRegion { (public)
 	size_t size() const override;
 
 public:
-	void set_permissions(bool read, bool write, bool execute) override;
-	void set_start(edb::address_t address) override;
-	void set_end(edb::address_t address) override;
+	void setPermissions(bool read, bool write, bool execute) override;
+	void setStart(edb::address_t address) override;
+	void setEnd(edb::address_t address) override;
 
 public:
 	edb::address_t start() const override;

SUBDIRS=pcf

noinst_PROGRAMS = test-import-export

test_import_export_SOURCES = \
	test-import-export.c

test_import_export_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(DBUS_CFLAGS)

test_import_export_LDADD = \
	$(GTHREAD_LIBS) \
	$(GTK_LIBS) \
	$(DBUS_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(top_builddir)/properties/libnm-vpn-plugin-vpnc.la

if WITH_TESTS

check-local: test-import-export
	$(abs_builddir)/test-import-export $(abs_srcdir)/pcf $(abs_builddir)/pcf

endif


SUBDIRS=pcf

noinst_PROGRAMS = test-import-export

test_import_export_SOURCES = \
	test-import-export.c

test_import_export_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(NM_CFLAGS) \
	$(NMGTK_CFLAGS) \
	$(DBUS_CFLAGS)

test_import_export_LDADD = \
	$(GTHREAD_LIBS) \
	$(GTK_LIBS) \
	$(DBUS_LIBS) \
	$(NM_LIBS) \
	$(NMGTK_LIBS) \
	$(top_builddir)/properties/libnm-vpnc-properties.la

if WITH_TESTS

check-local: test-import-export
	$(abs_builddir)/test-import-export $(abs_srcdir)/pcf $(abs_builddir)/pcf

endif


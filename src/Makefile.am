AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
	-I"$(top_srcdir)/shared/" \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\" \
	-DNM_VPNC_LOCALEDIR=\"$(datadir)/locale\"

libexec_PROGRAMS = nm-vpnc-service nm-vpnc-service-vpnc-helper

###############################################################################

nm_vpnc_service_SOURCES = \
	$(top_srcdir)/shared/nm-service-defines.h \
	nm-vpnc-service.c \
	nm-vpnc-service.h \
	utils.c \
	utils.h

nm_vpnc_service_LDADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
	$(top_builddir)/shared/libnm-vpn-plugin-vpnc-shared.la

###############################################################################

nm_vpnc_service_vpnc_helper_SOURCES = \
	nm-vpnc-service-vpnc-helper.c

nm_vpnc_service_vpnc_helper_LDADD = \
	$(GTHREAD_LIBS) \
	$(LIBNM_LIBS) \
	$(top_builddir)/shared/libnm-vpn-plugin-vpnc-shared.la

###############################################################################

noinst_PROGRAMS = test-vpnc-output

test_vpnc_output_SOURCES = \
	test-vpnc-output.c \
	utils.c \
	utils.h

test_vpnc_output_LDADD = $(GLIB_LIBS)

TESTS = \
	test-vpnc-output

CLEANFILES = *~

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

shared_sources = \
	$(top_srcdir)/shared/nm-utils/nm-shared-utils.c \
	$(top_srcdir)/shared/nm-utils/nm-shared-utils.h \
	$(top_srcdir)/shared/nm-utils/nm-vpn-plugin-macros.h \
	$(top_srcdir)/shared/nm-service-defines.h \
	$(NULL)

###############################################################################

nm_vpnc_service_SOURCES = \
	$(shared_sources) \
	nm-vpnc-service.c \
	nm-vpnc-service.h \
	utils.c \
	utils.h

nm_vpnc_service_LDADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)

###############################################################################

nm_vpnc_service_vpnc_helper_SOURCES = \
	$(shared_sources) \
	nm-vpnc-service-vpnc-helper.c

nm_vpnc_service_vpnc_helper_LDADD = \
	$(GTHREAD_LIBS) \
	$(LIBNM_LIBS)

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

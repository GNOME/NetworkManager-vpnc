INCLUDES = -I${top_srcdir} 

AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GTHREAD_CFLAGS) \
	$(NM_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DVERSION="\"$(VERSION)\"" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\"

libexec_PROGRAMS = nm-vpnc-service nm-vpnc-service-vpnc-helper

nm_vpnc_service_SOURCES = \
	nm-vpnc-service.c \
	nm-vpnc-service.h


nm_vpnc_service_LDADD = \
	$(DBUS_LIBS) \
	$(GTHREAD_LIBS) \
	$(NM_LIBS)


nm_vpnc_service_vpnc_helper_SOURCES = \
				nm-vpnc-service-vpnc-helper.c

nm_vpnc_service_vpnc_helper_LDADD = \
	$(DBUS_LIBS) \
	$(GTHREAD_LIBS) \
	$(NM_LIBS)

CLEANFILES = *~

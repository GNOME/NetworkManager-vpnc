libexec_PROGRAMS = nm-vpnc-auth-dialog

nm_vpnc_auth_dialog_CPPFLAGS = \
	$(LIBNM_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(LIBSECRET_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"

nm_vpnc_auth_dialog_SOURCES = \
	main.c

nm_vpnc_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBSECRET_LIBS)

CLEANFILES = *~


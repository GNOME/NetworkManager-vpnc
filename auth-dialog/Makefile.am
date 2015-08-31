libexec_PROGRAMS = nm-vpnc-auth-dialog

nm_vpnc_auth_dialog_CPPFLAGS = \
	$(LIBNM_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(LIBSECRET_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGNOME_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

nm_vpnc_auth_dialog_SOURCES = \
	main.c

nm_vpnc_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBSECRET_LIBS)

@INTLTOOL_DESKTOP_RULE@
desktopdir = $(datadir)/applications
desktop_in_in_files = nm-vpnc-auth-dialog.desktop.in.in
desktop_in_files = nm-vpnc-auth-dialog.desktop.in
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)

EXTRA_DIST = \
	$(desktop_in_in_files)

CLEANFILES = \
	*~ \
	$(desktop_DATA)

DISTCLEANFILES = \
	$(desktop_in_files)

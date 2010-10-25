INCLUDES = -I${top_srcdir}

libexec_PROGRAMS = nm-vpnc-auth-dialog

nm_vpnc_auth_dialog_CPPFLAGS = \
	$(NETWORKMANAGER_CFLAGS) \
	$(GTHREAD_CFLAGS) \
	$(GTK_CFLAGS) \
	$(GCONF_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DGLADEDIR=\""$(gladedir)"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED \
	-DGNOME_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

nm_vpnc_auth_dialog_SOURCES = \
	main.c \
	gnome-two-password-dialog.c \
	gnome-two-password-dialog.h

nm_vpnc_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(GCONF_LIBS) \
	$(top_builddir)/common-gnome/libnm-vpnc-common-gnome.la

CLEANFILES = *~


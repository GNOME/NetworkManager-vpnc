SUBDIRS=. tests

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpnc-properties.la

libnm_vpnc_properties_la_SOURCES = \
	nm-vpnc.c \
	nm-vpnc.h \
	nm-vpnc-helper.c \
	nm-vpnc-helper.h

uidir = $(datadir)/gnome-vpn-properties/vpnc
ui_DATA = nm-vpnc-dialog.ui

libnm_vpnc_properties_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(NM_CFLAGS) \
	$(NMGTK_CFLAGS) \
	-I$(top_srcdir)/src \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

libnm_vpnc_properties_la_LIBADD = \
	$(GTK_LIBS) \
	$(NM_LIBS) \
	$(NMGTK_LIBS)

libnm_vpnc_properties_la_LDFLAGS = \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST = $(ui_DATA)

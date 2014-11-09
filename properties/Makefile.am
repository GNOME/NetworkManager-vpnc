SUBDIRS=. tests

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-vpnc.la libnm-vpnc-properties.la

libnm_vpn_plugin_vpnc_la_SOURCES = \
	nm-vpnc.c \
	nm-vpnc.h \
	nm-vpnc-helper.c \
	nm-vpnc-helper.h

libnm_vpnc_properties_la_SOURCES = \
	$(libnm_vpn_plugin_vpnc_la_SOURCES)

uidir = $(datadir)/gnome-vpn-properties/vpnc
ui_DATA = nm-vpnc-dialog.ui

common_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	-I$(top_srcdir)/src/ \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

libnm_vpn_plugin_vpnc_la_CFLAGS = \
	$(common_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS)

libnm_vpnc_properties_la_CFLAGS = \
	-DNM_VPNC_OLD \
	$(common_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS) \
	$(LIBNM_GTK_CFLAGS)

libnm_vpnc_properties_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(LIBNM_GTK_LIBS)

libnm_vpn_plugin_vpnc_new_la_LDFLAGS = \
	-avoid-version

libnm_vpnc_properties_la_LDFLAGS = \
	$(libnm_vpn_plugin_vpnc_new_la_LDFLAGS)

CLEANFILES = *.bak *~

EXTRA_DIST = $(ui_DATA)

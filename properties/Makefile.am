SUBDIRS=. tests

INCLUDES = -I${top_srcdir}

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpnc-properties.la

libnm_vpnc_properties_la_SOURCES = \
	pcf-file.c \
	pcf-file.h \
	nm-vpnc.c \
	nm-vpnc.h

uidir = $(datadir)/gnome-vpn-properties/vpnc
ui_DATA = nm-vpnc-dialog.ui

libnm_vpnc_properties_la_CPPFLAGS = \
	$(GTK_CFLAGS) \
	$(GCONF_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	$(NETWORKMANAGER_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED \
	-DGNOME_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

libnm_vpnc_properties_la_LIBADD = \
	$(GTK_LIBS) \
	$(GCONF_LIBS) \
	$(NETWORKMANAGER_LIBS) \
	$(GNOMEKEYRING_LIBS) \
	$(top_builddir)/common-gnome/libnm-vpnc-common-gnome.la

libnm_vpnc_properties_la_LDFLAGS = \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST = $(ui_DATA)

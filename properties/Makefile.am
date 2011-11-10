SUBDIRS=. tests

INCLUDES = -I${top_srcdir}

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
	$(GTK_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	$(NM_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGNOME_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

libnm_vpnc_properties_la_LIBADD = \
	$(GTK_LIBS) \
	$(NM_LIBS) \
	$(GNOMEKEYRING_LIBS)

libnm_vpnc_properties_la_LDFLAGS = \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST = $(ui_DATA)

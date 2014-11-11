SUBDIRS=. tests

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpnc-properties-new.la libnm-vpnc-properties-old.la

libnm_vpnc_properties_new_la_SOURCES = \
	nm-vpnc.c \
	nm-vpnc.h \
	nm-vpnc-helper.c \
	nm-vpnc-helper.h \
	nm-vpnc-properties.h

libnm_vpnc_properties_old_la_SOURCES = \
	nm-vpnc.c \
	nm-vpnc.h \
	nm-vpnc-helper.c \
	nm-vpnc-helper.h

uidir = $(datadir)/gnome-vpn-properties/vpnc
ui_DATA = nm-vpnc-dialog.ui

libnm_vpnc_properties_new_la_CPPFLAGS = \
	-DNM_VPNC_NEW \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	-I$(top_srcdir)/src/ \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

libnm_vpnc_properties_new_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS)

libnm_vpnc_properties_new_la_LDFLAGS = \
        -avoid-version

nm-vpnc-properties.h: nm-vpnc-properties.xml
	$(AM_V_GEN) (echo "/* Auto-generated. Do not edit. */"; echo ""; echo "#define NM_VPNC_PROPERTIES_XML \\"; sed -e 's/ _label=/ label=/;' -e 's/"/\\"/g' -e 's/\(.*\)/"\1" \\/' $^; echo '""') > $@

BUILT_SOURCES = nm-vpnc-properties.h

libnm_vpnc_properties_old_la_CPPFLAGS = \
	-DNM_VPNC_OLD \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(NM_CFLAGS) \
	-I$(top_srcdir)/src \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

libnm_vpnc_properties_old_la_LIBADD = \
	$(GTK_LIBS) \
	$(NM_LIBS)

libnm_vpnc_properties_old_la_LDFLAGS = \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST = $(ui_DATA) nm-vpnc-properties.xml

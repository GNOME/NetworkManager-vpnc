SUBDIRS=. tests

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-vpnc.la
if WITH_GNOME
plugin_LTLIBRARIES += libnm-vpn-plugin-vpnc-editor.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-vpnc-properties.la
endif
endif

shared_sources = \
    $(top_srcdir)/shared/nm-service-defines.h \
    $(NULL)

plugin_sources = \
    nm-vpnc-helper.c \
    nm-vpnc-helper.h \
    nm-vpnc-editor-plugin.c \
    nm-vpnc-editor-plugin.h

editor_sources = \
    nm-vpnc-editor.c \
    nm-vpnc-editor.h

uidir = $(datadir)/gnome-vpn-properties/vpnc
if WITH_GNOME
ui_DATA = nm-vpnc-dialog.ui
endif

common_CFLAGS = \
    $(GLIB_CFLAGS) \
    -I"$(top_srcdir)/shared/" \
    -DICONDIR=\""$(datadir)/pixmaps"\" \
    -DUIDIR=\""$(uidir)"\" \
    -DLOCALEDIR=\"$(datadir)/locale\"

###############################################################################

libnm_vpn_plugin_vpnc_la_SOURCES = \
    $(shared_sources) \
    $(top_srcdir)/shared/nm-utils/nm-vpn-plugin-utils.c \
    $(top_srcdir)/shared/nm-utils/nm-vpn-plugin-utils.h \
    $(plugin_sources)

libnm_vpn_plugin_vpnc_la_CFLAGS = \
    -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
    -DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
    $(common_CFLAGS) \
    $(LIBNM_CFLAGS)

libnm_vpn_plugin_vpnc_la_LIBADD = \
    $(LIBNM_LIBS) \
    $(LD_LIBS) \
    $(NULL)

libnm_vpn_plugin_vpnc_la_LDFLAGS = \
    -avoid-version \
    -Wl,--version-script=$(srcdir)/libnm-vpn-plugin-vpnc.ver

###############################################################################

libnm_vpn_plugin_vpnc_editor_la_SOURCES = \
    $(shared_sources) \
    $(editor_sources)

libnm_vpn_plugin_vpnc_editor_la_CFLAGS = \
    -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
    $(common_CFLAGS) \
    $(GTK_CFLAGS) \
    $(LIBNM_CFLAGS) \
    $(LIBNMA_CFLAGS)

libnm_vpn_plugin_vpnc_editor_la_LIBADD = \
    $(GTK_LIBS) \
    $(LIBNM_LIBS) \
    $(LIBNMA_LIBS)

libnm_vpn_plugin_vpnc_editor_la_LDFLAGS = \
    -avoid-version \
    -Wl,--version-script=$(srcdir)/libnm-vpn-plugin-vpnc-editor.ver

###############################################################################

libnm_vpnc_properties_la_SOURCES = \
    $(shared_sources) \
    $(plugin_sources) \
    $(editor_sources)

libnm_vpnc_properties_la_CFLAGS = \
    -DNM_VPN_OLD \
    -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
    $(common_CFLAGS) \
    $(GTK_CFLAGS) \
    $(LIBNM_GLIB_CFLAGS) \
    $(LIBNM_GTK_CFLAGS)

libnm_vpnc_properties_la_LIBADD = \
    $(GTK_LIBS) \
    $(LIBNM_GLIB_LIBS) \
    $(LIBNM_GTK_LIBS)

libnm_vpnc_properties_la_LDFLAGS = \
    -avoid-version \
    -Wl,--version-script=$(srcdir)/libnm-vpnc-properties.ver

###############################################################################

libnm_vpn_plugin_vpnc_test_la_SOURCES = $(libnm_vpn_plugin_vpnc_la_SOURCES)
libnm_vpn_plugin_vpnc_test_la_CFLAGS = $(libnm_vpn_plugin_vpnc_la_CFLAGS)
libnm_vpn_plugin_vpnc_test_la_LIBADD = $(libnm_vpn_plugin_vpnc_la_LIBADD)
libnm_vpn_plugin_vpnc_test_la_LDFLAGS = \
    -avoid-version

libnm_vpnc_properties_test_la_SOURCES = $(libnm_vpnc_properties_la_SOURCES)
libnm_vpnc_properties_test_la_CFLAGS = $(libnm_vpnc_properties_la_CFLAGS)
libnm_vpnc_properties_test_la_LIBADD = $(libnm_vpnc_properties_la_LIBADD)
libnm_vpnc_properties_test_la_LDFLAGS = \
    -avoid-version

###############################################################################

noinst_LTLIBRARIES = \
    libnm-vpn-plugin-vpnc-test.la
if WITH_LIBNM_GLIB
noinst_LTLIBRARIES += libnm-vpnc-properties-test.la
endif

CLEANFILES = *.bak *~

EXTRA_DIST = \
    libnm-vpn-plugin-vpnc.ver \
    libnm-vpn-plugin-vpnc-editor.ver \
    libnm-vpnc-properties.ver \
    nm-vpnc-dialog.ui

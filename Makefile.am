AUTOMAKE_OPTIONS = subdir-objects

SUBDIRS = . po

libexec_PROGRAMS =

noinst_PROGRAMS =

noinst_LTLIBRARIES =

TESTS =

###############################################################################

common_cppflags = \
	$(GLIB_CFLAGS) \
	-I"$(top_srcdir)/shared/"

shared_sources = \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h \
	shared/nm-utils/nm-vpn-plugin-macros.h \
	shared/nm-service-defines.h \
	$(NULL)

###############################################################################

libexec_PROGRAMS += src/nm-vpnc-service

src_nm_vpnc_service_CPPFLAGS = \
	$(common_cppflags) \
	$(LIBNM_CFLAGS) \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DNM_VPNC_LOCALEDIR=\"$(datadir)/locale\"
	$(NULL)

src_nm_vpnc_service_SOURCES = \
	$(shared_sources) \
	src/nm-vpnc-service.c \
	src/nm-vpnc-service.h \
	src/utils.c \
	src/utils.h

src_nm_vpnc_service_LDADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)

###############################################################################

libexec_PROGRAMS += src/nm-vpnc-service-vpnc-helper

src_nm_vpnc_service_vpnc_helper_CPPFLAGS = \
	$(common_cppflags) \
	$(LIBNM_CFLAGS)

src_nm_vpnc_service_vpnc_helper_SOURCES = \
	$(shared_sources) \
	src/nm-vpnc-service-vpnc-helper.c

src_nm_vpnc_service_vpnc_helper_LDADD = \
	$(GTHREAD_LIBS) \
	$(LIBNM_LIBS)

###############################################################################

noinst_PROGRAMS += src/test-vpnc-output
TESTS += src/test-vpnc-output

src_test_vpnc_output_CPPFLAGS = \
	$(common_cppflags) \
	$(LIBNM_CFLAGS)

src_test_vpnc_output_SOURCES = \
	src/test-vpnc-output.c \
	src/utils.c \
	src/utils.h

src_test_vpnc_output_LDADD = \
	$(GLIB_LIBS)

###############################################################################

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = properties/libnm-vpn-plugin-vpnc.la
if WITH_GNOME
plugin_LTLIBRARIES += properties/libnm-vpn-plugin-vpnc-editor.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += properties/libnm-vpnc-properties.la
endif
endif
if WITH_GTK4
plugin_LTLIBRARIES += properties/libnm-gtk4-vpn-plugin-vpnc-editor.la
endif

properties/resources.h: properties/gresource.xml
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-header --internal

properties/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir)/properties --generate-dependencies $(srcdir)/properties/gresource.xml)
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-source --internal

gtk4/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --generate-dependencies $(srcdir)/properties/gresource.xml |sed "s,^,$(builddir)/gtk4/,")
	@mkdir -p $(builddir)/gtk4
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/gtk4 --sourcedir=$(builddir)/gtk4 --generate-source --internal

gtk4/%.ui: properties/%.ui
	@mkdir -p $(builddir)/gtk4
	gtk4-builder-tool simplify --3to4 $< |grep -v can-default >$@

plugin_sources = \
	properties/nm-vpnc-helper.c \
	properties/nm-vpnc-helper.h \
	properties/nm-vpnc-editor-plugin.c \
	properties/nm-vpnc-editor-plugin.h

editor_sources = \
	properties/nm-vpnc-editor.c \
	properties/nm-vpnc-editor.h

###############################################################################

properties_libnm_vpn_plugin_vpnc_la_SOURCES = \
	$(shared_sources) \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	$(plugin_sources)

properties_libnm_vpn_plugin_vpnc_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	$(common_cppflags) \
	$(LIBNM_CFLAGS)

properties_libnm_vpn_plugin_vpnc_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
	$(DL_LIBS) \
	$(NULL)

properties_libnm_vpn_plugin_vpnc_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/properties/libnm-vpn-plugin-vpnc.ver

###############################################################################

properties_libnm_gtk4_vpn_plugin_vpnc_editor_la_SOURCES = \
	$(shared_sources) \
	$(editor_sources)

nodist_properties_libnm_gtk4_vpn_plugin_vpnc_editor_la_SOURCES = \
	properties/resources.h \
	gtk4/resources.c

properties_libnm_gtk4_vpn_plugin_vpnc_editor_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(common_cppflags) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_GTK4_CFLAGS)

properties_libnm_gtk4_vpn_plugin_vpnc_editor_la_LIBADD = \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_GTK4_LIBS)

properties_libnm_gtk4_vpn_plugin_vpnc_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/properties/libnm-vpn-plugin-vpnc-editor.ver

###############################################################################

properties_libnm_vpn_plugin_vpnc_editor_la_SOURCES = \
	$(shared_sources) \
	$(editor_sources)

nodist_properties_libnm_vpn_plugin_vpnc_editor_la_SOURCES = \
	properties/resources.h \
	properties/resources.c

properties_libnm_vpn_plugin_vpnc_editor_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(common_cppflags) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS)

properties_libnm_vpn_plugin_vpnc_editor_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS)

properties_libnm_vpn_plugin_vpnc_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/properties/libnm-vpn-plugin-vpnc-editor.ver

###############################################################################

properties_libnm_vpnc_properties_la_SOURCES = \
	$(shared_sources) \
	$(plugin_sources) \
	$(editor_sources)

nodist_properties_libnm_vpnc_properties_la_SOURCES = \
	properties/resources.h \
	properties/resources.c

properties_libnm_vpnc_properties_la_CFLAGS = \
	-DNM_VPN_OLD \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	-DLOCALEDIR=\"$(datadir)/locale\"
	$(common_cppflags) \
	$(GTK_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS) \
	$(LIBNM_GTK_CFLAGS)

properties_libnm_vpnc_properties_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(LIBNM_GTK_LIBS)

properties_libnm_vpnc_properties_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/libnm-vpnc-properties.ver

###############################################################################

noinst_LTLIBRARIES += properties/libnm-vpn-plugin-vpnc-test.la

properties_libnm_vpn_plugin_vpnc_test_la_SOURCES = $(properties_libnm_vpn_plugin_vpnc_la_SOURCES)
properties_libnm_vpn_plugin_vpnc_test_la_CFLAGS = $(properties_libnm_vpn_plugin_vpnc_la_CFLAGS)
properties_libnm_vpn_plugin_vpnc_test_la_LIBADD = $(properties_libnm_vpn_plugin_vpnc_la_LIBADD)
properties_libnm_vpn_plugin_vpnc_test_la_LDFLAGS = \
	-avoid-version

if WITH_LIBNM_GLIB
noinst_LTLIBRARIES += properties/libnm-vpnc-properties-test.la
endif

properties_libnm_vpnc_properties_test_la_SOURCES = $(properties_libnm_vpnc_properties_la_SOURCES)
properties_libnm_vpnc_properties_test_la_CFLAGS = $(properties_libnm_vpnc_properties_la_CFLAGS)
properties_libnm_vpnc_properties_test_la_LIBADD = $(properties_libnm_vpnc_properties_la_LIBADD)
properties_libnm_vpnc_properties_test_la_LDFLAGS = \
	-avoid-version

###############################################################################

test_cppflags = \
	-I${top_srcdir}/shared \
	-I${top_srcdir}/properties \
	-DTEST_SRCDIR="\"$(abs_srcdir)/properties/tests\"" \
	-DTEST_BUILDDIR="\"$(abs_builddir)/properties/tests\"" \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS)

noinst_PROGRAMS += properties/tests/test-import-export

TESTS += properties/tests/test-import-export

properties_tests_test_import_export_SOURCES = \
	properties/tests/test-import-export.c

properties_tests_test_import_export_CPPFLAGS = \
	$(test_cppflags) \
	$(LIBNM_CFLAGS)

properties_tests_test_import_export_LDADD = \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
	$(top_builddir)/properties/libnm-vpn-plugin-vpnc-test.la

if WITH_LIBNM_GLIB
noinst_PROGRAMS += properties/tests/test-import-export-glib
TESTS += properties/tests/test-import-export-glib
endif

properties_tests_test_import_export_glib_SOURCES = \
	properties/tests/test-import-export.c

properties_tests_test_import_export_glib_CPPFLAGS = \
	-DNM_VPN_OLD \
	$(test_cppflags) \
	$(LIBNM_GLIB_CFLAGS) \
	$(LIBNM_GTK_CFLAGS)

properties_tests_test_import_export_glib_LDADD = \
	$(GTHREAD_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(LIBNM_GTK_LIBS) \
	$(top_builddir)/properties/libnm-vpnc-properties-test.la

###############################################################################

libexec_PROGRAMS += auth-dialog/nm-vpnc-auth-dialog

auth_dialog_nm_vpnc_auth_dialog_CPPFLAGS = \
	$(common_cppflags) \
	$(GTK_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(LIBSECRET_CFLAGS)

auth_dialog_nm_vpnc_auth_dialog_SOURCES = \
	auth-dialog/main.c

auth_dialog_nm_vpnc_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBSECRET_LIBS)

###############################################################################

dbusservicedir = $(datadir)/dbus-1/system.d
dbusservice_DATA = nm-vpnc-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-vpnc-service.name

if WITH_LIBNM_GLIB
# Install a file with full path to plugins for an old gnome-shell
# https://bugzilla.gnome.org/show_bug.cgi?id=693590
install-data-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/NetworkManager/VPN
	sed -e "1s|^|# This file is obsoleted by a file in $(NM_VPN_SERVICE_DIR)\n\n|" \
	    -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]|@NM_PLUGIN_DIR@|g' \
	    <$(srcdir)/nm-vpnc-service.name.in \
	    >$(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-vpnc-service.name

uninstall-hook:
	 rm -f $(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-vpnc-service.name
endif

appdatadir = $(datadir)/metainfo
appdata_files = $(appdata_in_files:.xml.in=.xml)
if WITH_GNOME
appdata_DATA = $(appdata_files)
endif
appdata_in_files = appdata/network-manager-vpnc.metainfo.xml.in
@INTLTOOL_XML_RULE@

nm-vpnc-service.name: $(srcdir)/nm-vpnc-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $^ >$@

DISTCHECK_CONFIGURE_FLAGS = \
	--with-tests=yes \
	--enable-more-warnings=yes \
	--with-gtk4

EXTRA_DIST = \
	properties/libnm-vpn-plugin-vpnc.ver \
	properties/libnm-vpn-plugin-vpnc-editor.ver \
	properties/libnm-vpnc-properties.ver \
	properties/nm-vpnc-dialog.ui \
	properties/gresource.xml \
	\
	properties/tests/pcf/basic.pcf \
	properties/tests/pcf/everything-via-vpn.pcf \
	properties/tests/pcf/no-natt.pcf \
	properties/tests/pcf/always-ask.pcf \
	properties/tests/pcf/iso885915.pcf \
	properties/tests/pcf/nat-cisco.pcf \
	properties/tests/pcf/natt.pcf \
	properties/tests/pcf/force-natt.pcf \
	properties/tests/pcf/use-legacy-ike-port-0.pcf \
	properties/tests/pcf/use-legacy-ike-port-1.pcf \
	\
	shared/README \
	shared/nm-utils/gsystem-local-alloc.h \
	shared/nm-utils/nm-glib.h \
	shared/nm-utils/nm-macros-internal.h \
	shared/nm-utils/nm-test-utils.h \
	shared/nm-default.h \
	shared/nm-service-defines.h \
	\
	nm-vpnc-service.name.in \
	$(dbusservice_DATA)  \
	$(appdata_in_files)  \
	$(appdata_files)     \
	intltool-extract.in  \
	intltool-merge.in    \
	intltool-update.in

# Include a prebuilt file in tarball, to avoid hitting
# https://gitlab.gnome.org/GNOME/gtk/-/merge_requests/4415
EXTRA_DIST += \
	gtk4/nm-vpnc-dialog.ui

CLEANFILES = *.bak *~ \
	$(nmvpnservice_DATA) \
	$(appdata_files) \
	properties/resources.c \
	properties/resources.h \
	gtk4/resources.c \
	gtk4/nm-vpnc-dialog.ui

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4

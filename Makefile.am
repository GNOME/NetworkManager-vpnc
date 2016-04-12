AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

if WITH_GNOME
SUBDIRS += auth-dialog properties po
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-vpnc-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-vpnc-service.name

if WITH_LIBNM_GLIB
nmvpnoldservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnoldservice_DATA = nm-vpnc-service.name
endif

appdatadir = $(datadir)/appdata
appdata_DATA = $(appdata_in_files:.xml.in=.xml)
appdata_in_files = appdata/network-manager-vpnc.appdata.xml.in
@INTLTOOL_XML_RULE@

nm-vpnc-service.name: $(srcdir)/nm-vpnc-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]|$(libdir)/NetworkManager|g' \
	    $< >$@

DISTCHECK_CONFIGURE_FLAGS = \
	--with-tests=yes \
	--enable-more-warnings=yes

EXTRA_DIST = nm-vpnc-service.name.in \
             $(dbusservice_DATA)  \
             $(appdata_in_files)  \
             $(appdata_DATA)      \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in \
             nm-test-helpers.h

CLEANFILES = $(nmvpnservice_DATA) \
             $(appdata_DATA)

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4

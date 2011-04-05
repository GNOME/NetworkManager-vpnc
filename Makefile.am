AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

if WITH_GNOME
SUBDIRS += common-gnome auth-dialog properties po
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-vpnc-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-vpnc-service.name

desktopfile = nm-vpnc.desktop.in
iconfile = gnome-mime-application-x-cisco-vpn-settings.png

if WITH_GNOME
# FIXME: uncomment when nmce gets --import support
#desktopdir = $(datadir)/applications
#desktop_in_files = $(desktopfile)
#desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)
#@INTLTOOL_DESKTOP_RULE@

icondir = $(datadir)/icons/hicolor/48x48/apps
icon_DATA = $(iconfile)
endif

nm-vpnc-service.name: $(srcdir)/nm-vpnc-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' $< >$@

DISTCHECK_CONFIGURE_FLAGS = --with-tests=yes

EXTRA_DIST = nm-vpnc-service.name.in \
             $(dbusservice_DATA)  \
             $(desktopfile) \
             $(iconfile) \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in \
             nm-test-helpers.h

CLEANFILES = $(nmvpnservice_DATA) $(desktop_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4

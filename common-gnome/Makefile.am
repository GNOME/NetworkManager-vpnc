noinst_LTLIBRARIES=libnm-vpnc-common-gnome.la

libnm_vpnc_common_gnome_la_CPPFLAGS = \
	$(NETWORKMANAGER_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	-DG_DISABLE_DEPRECATED

libnm_vpnc_common_gnome_la_SOURCES= \
	keyring-helpers.c \
	keyring-helpers.h

libnm_vpnc_common_gnome_la_LIBADD = \
	$(NETWORKMANAGER_LIBS) \
	$(GLIB_LIBS) \
	$(GNOMEKEYRING_LIBS)


/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-vpnc-service - vpnc integration with NetworkManager
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <locale.h>

#include "utils.h"
#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

extern char **environ;

static struct {
	int log_level;
	const char *log_prefix_token;
} gl/*obal*/;

/*****************************************************************************/

#define _NMLOG(level, ...) \
	G_STMT_START { \
		if (gl.log_level >= (level)) { \
			g_print ("nm-vpnc[%s]: %-7s [helper-%ld] " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
			         gl.log_prefix_token ?: "???", \
			         nm_utils_syslog_to_str (level), \
			         (long) getpid () \
			         _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
		} \
	} G_STMT_END

#define _LOGD(...) _NMLOG(LOG_INFO,    __VA_ARGS__)
#define _LOGI(...) _NMLOG(LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(LOG_WARNING, __VA_ARGS__)

/*****************************************************************************/

static void
helper_failed (GDBusProxy *proxy, const char *reason)
{
	gs_free_error GError *err = NULL;

	_LOGW ("nm-nvpnc-service-vpnc-helper did not receive a valid %s from vpnc", reason);

	if (!g_dbus_proxy_call_sync (proxy,
	                             "SetFailure",
	                             g_variant_new ("(s)", reason),
	                             G_DBUS_CALL_FLAGS_NONE, -1,
	                             NULL,
	                             &err)) {
		_LOGW ("Could not send failure information: %s", err->message);
	}

	exit (1);
}

static void
send_config (GDBusProxy *proxy, GVariant *config, GVariant *ip4config)
{
	GError *err = NULL;

	if (!g_dbus_proxy_call_sync (proxy,
	                             "SetConfig",
	                             g_variant_new ("(*)", config),
	                             G_DBUS_CALL_FLAGS_NONE,
	                             -1,
	                             NULL,
	                             &err)) {
		_LOGW ("Could not send configuration: %s", err->message);
		g_error_free (err);
	}

	if (ip4config) {
		if (!g_dbus_proxy_call_sync (proxy,
		                             "SetIp4Config",
		                             g_variant_new ("(*)", ip4config),
		                             G_DBUS_CALL_FLAGS_NONE,
		                             -1,
		                             NULL,
		                             &err)) {
			_LOGW ("Could not send IPv4 configuration: %s", err->message);
			g_error_free (err);
		}
	}
}

static GVariant *
str_to_gvariant (const char *str, gboolean try_convert)
{

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (!g_utf8_validate (str, -1, NULL)) {
		if (try_convert && !(str = g_convert (str, -1, "ISO-8859-1", "UTF-8", NULL, NULL, NULL)))
			str = g_convert (str, -1, "C", "UTF-8", NULL, NULL, NULL);

		if (!str)
			/* Invalid */
			return NULL;
	}

	return g_variant_new_string (str);
}

static GVariant *
addr4_to_gvariant (const char *str)
{
        struct in_addr  temp_addr;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET, str, &temp_addr) <= 0)
		return NULL;

	return g_variant_new_uint32 (temp_addr.s_addr);
}

static GVariant *
addr4_list_to_gvariant (const char *str)
{
	GVariantBuilder builder;
	char **split;
	int i;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	split = g_strsplit (str, " ", -1);
	if (g_strv_length (split) == 0)
		return NULL;

	g_variant_builder_init (&builder, G_VARIANT_TYPE_ARRAY);

	for (i = 0; split[i]; i++) {
		struct in_addr addr;

		if (inet_pton (AF_INET, split[i], &addr) > 0) {
			g_variant_builder_add_value (&builder, g_variant_new_uint32 (addr.s_addr));
		} else {
			g_strfreev (split);
			g_variant_unref (g_variant_builder_end (&builder));
			return NULL;
		}
	}

	g_strfreev (split);

	return g_variant_builder_end (&builder);
}

static GVariant *
split_dns_list_to_gvariant (const char *str)
{
	gchar **split;

	if (!str || strlen (str) < 1)
		return NULL;

	split = g_strsplit (str, ",", -1);
	if (g_strv_length (split) == 0)
		return NULL;

	return g_variant_new_strv ((const gchar **) split, -1);
}

static GVariant *
get_ip4_routes (void)
{
	GVariantBuilder builder;
	GVariant *value;
	char *tmp;
	int num, i, size = 0;

#define BUFLEN 256

	tmp = getenv ("CISCO_SPLIT_INC");
	if (!tmp || strlen (tmp) < 1)
		return NULL;

	num = atoi (tmp);
	if (!num)
		return NULL;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aau"));

	for (i = 0; i < num; i++) {
		GVariantBuilder array;
		char buf[BUFLEN];
		struct in_addr network;
		guint32 next_hop = 0; /* no next hop */
		guint32 prefix, metric = 0;

		snprintf (buf, BUFLEN, "CISCO_SPLIT_INC_%d_ADDR", i);
		tmp = getenv (buf);
		if (!tmp || inet_pton (AF_INET, tmp, &network) <= 0) {
			_LOGW ("Ignoring invalid static route address '%s'", tmp ? tmp : "NULL");
			continue;
		}

		snprintf (buf, BUFLEN, "CISCO_SPLIT_INC_%d_MASKLEN", i);
		tmp = getenv (buf);
		if (tmp) {
			long int tmp_prefix;

			errno = 0;
			tmp_prefix = strtol (tmp, NULL, 10);
			if (errno || tmp_prefix <= 0 || tmp_prefix > 32) {
				_LOGW ("Ignoring invalid static route prefix '%s'", tmp ? tmp : "NULL");
				continue;
			}
			prefix = (guint32) tmp_prefix;
		} else {
			struct in_addr netmask;

			snprintf (buf, BUFLEN, "CISCO_SPLIT_INC_%d_MASK", i);
			tmp = getenv (buf);
			if (!tmp || inet_pton (AF_INET, tmp, &netmask) <= 0) {
				_LOGW ("Ignoring invalid static route netmask '%s'", tmp ? tmp : "NULL");
				continue;
			}
			prefix = nm_utils_ip4_netmask_to_prefix (netmask.s_addr);
		}

		g_variant_builder_init (&array, G_VARIANT_TYPE ("au"));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (network.s_addr));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (prefix));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (next_hop));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (metric));
		g_variant_builder_add_value (&builder, g_variant_builder_end (&array));
		size++;
	}

	value = g_variant_builder_end (&builder);
	if (size > 0)
		return value;

	g_variant_unref (value);
	return NULL;
}

/*
 * Environment variables passed back from 'vpnc':
 *
 * VPNGATEWAY             -- vpn gateway address (always present)
 * TUNDEV                 -- tunnel device (always present)
 * INTERNAL_IP4_ADDRESS   -- address (always present)
 * INTERNAL_IP4_NETMASK   -- netmask (often unset)
 * INTERNAL_IP4_DNS       -- list of dns serverss
 * INTERNAL_IP4_NBNS      -- list of wins servers
 * CISCO_DEF_DOMAIN       -- default domain name
 * CISCO_BANNER           -- banner from server
 */
int
main (int argc, char *argv[])
{
	const char *bus_name = NM_DBUS_SERVICE_VPNC;
	gs_unref_object GDBusProxy *proxy = NULL;
	gs_unref_variant GVariant *ip4config = NULL;
	gs_unref_variant GVariant *config = NULL;
	gs_free_error GError *err = NULL;
	gboolean netmask_found = FALSE;
	struct in_addr temp_addr;
	gs_free char *str = NULL;
	GVariantBuilder ip4builder;
	GVariantBuilder builder;
	long int mtu = 1412;
	guint32 prefix = 0;
	GVariant *val;
	char **iter;
	char *tmp;
	int arg_i;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	tmp = getenv ("reason");
	if (tmp && strcmp (tmp, "connect") != 0) {
		/* vpnc 0.3.3 gives us a "reason" code.  If we are given one,
		 * don't proceed unless its "connect".
		 */
		return 0;
	}

	/* very basic command line parsing */
	if (argc <= 2) {
		g_printerr ("Missing arguments (requires <LEVEL> <PREFIX_TOKEN>)\n");
		return 1;
	}
	arg_i = 1;
	gl.log_level = _nm_utils_ascii_str_to_int64 (argv[arg_i++], 10, 0, LOG_DEBUG, 0);
	gl.log_prefix_token = argv[arg_i++];

	for (; arg_i < argc; arg_i++) {
		if (nm_streq (argv[arg_i], "--bus-name")) {
			if (++arg_i == argc) {
				g_printerr ("Missing bus name argument\n");
				return 1;
			}
			bus_name = argv[arg_i];
			if (!g_dbus_is_name (bus_name)) {
				g_printerr ("Invalid bus name argument\n");
				return 1;
			}
		}
	}

	_LOGD ("command line: %s", (str = g_strjoinv (" ", argv)));
	g_clear_pointer (&str, g_free);

	for (iter = environ; iter && *iter; iter++)
		_LOGD ("environment: %s", *iter);

	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                       G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                                       NULL,
	                                       bus_name,
	                                       NM_VPN_DBUS_PLUGIN_PATH,
	                                       NM_VPN_DBUS_PLUGIN_INTERFACE,
	                                       NULL, &err);
	if (!proxy) {
		_LOGW ("Could not create a D-Bus proxy: %s", err->message);
		return 1;
	}

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&ip4builder, G_VARIANT_TYPE_VARDICT);

	/* Gateway */
	val = addr4_to_gvariant (getenv ("VPNGATEWAY"));
	if (val)
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, val);
	else
		helper_failed (proxy, "VPN Gateway");

	/* Tunnel device */
	val = str_to_gvariant (getenv ("TUNDEV"), FALSE);
	if (val)
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_TUNDEV, val);
	else
		helper_failed (proxy, "Tunnel Device");

	/* Banner */
	val = str_to_gvariant (getenv ("CISCO_BANNER"), TRUE);
	if (val)
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_BANNER, val);

	/* MTU */
	tmp = getenv ("INTERNAL_IP4_MTU");
	if (tmp && strlen (tmp)) {
		errno = 0;
		mtu = strtol (tmp, NULL, 10);
		if (errno || mtu < 0 || mtu > 20000) {
			_LOGW ("Ignoring invalid tunnel MTU '%s'", tmp);
			mtu = 1412;
		}
	}
	g_variant_builder_add (&builder,
	                       "{sv}",
	                       NM_VPN_PLUGIN_CONFIG_MTU,
	                       g_variant_new_uint32 ((guint32) mtu));

	/* IPv4 configuration */
	/* IP address */
	val = addr4_to_gvariant (getenv ("INTERNAL_IP4_ADDRESS"));
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
	else
		helper_failed (proxy, "IP4 Address");

	/* PTP address; for vpnc PTP address == internal IP4 address */
	val = addr4_to_gvariant (getenv ("INTERNAL_IP4_ADDRESS"));
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);
	else
		helper_failed (proxy, "IP4 PTP Address");

	/* Netmask / Prefix */
	tmp = getenv ("INTERNAL_IP4_NETMASKLEN");
	if (tmp) {
		unsigned long pfx;

		errno = 0;
		pfx = strtoul (tmp, NULL, 10);
		if (pfx <= 32 && errno == 0)
			prefix = (guint32) pfx;
		netmask_found = TRUE;
	}
	if (!prefix) {
		tmp = getenv ("INTERNAL_IP4_NETMASK");
		if (tmp && inet_pton (AF_INET, tmp, &temp_addr) > 0)
			prefix = nm_utils_ip4_netmask_to_prefix (temp_addr.s_addr);
		netmask_found = TRUE;
	}
	if (netmask_found == FALSE) {
		/* If no netmask was given, that means point-to-point, ie /32 */
		prefix = 32;
	}
	if (prefix) {
		g_variant_builder_add (&ip4builder,
		                       "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_PREFIX,
		                       g_variant_new_uint32 (prefix));
	}

	/* DNS */
	val = addr4_list_to_gvariant (getenv ("INTERNAL_IP4_DNS"));
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DNS, val);

	/* WINS servers */
	val = addr4_list_to_gvariant (getenv ("INTERNAL_IP4_NBNS"));
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_NBNS, val);

	/* Default domain */
	val = str_to_gvariant (getenv ("CISCO_DEF_DOMAIN"), TRUE);
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN, val);

	/* Split DNS domains */
	val = split_dns_list_to_gvariant (getenv ("CISCO_SPLIT_DNS"));
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DOMAINS, val);

	/* Routes */
	val = get_ip4_routes ();
	if (val) {
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, val);
		/* If routes-to-include were provided, that means no default route */
		g_variant_builder_add (&ip4builder,
		                       "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT,
		                       g_variant_new_boolean (TRUE));
	}

	ip4config = g_variant_ref_sink (g_variant_builder_end (&ip4builder));

	if (g_variant_n_children (ip4config)) {
		val = g_variant_new_boolean (TRUE);
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP4, val);
	} else
		helper_failed (proxy, "IPv4 configuration");

	config = g_variant_ref_sink (g_variant_builder_end (&builder));

	send_config (proxy, config, ip4config);

	return 0;
}

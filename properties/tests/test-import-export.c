/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2009 Dan Williams, <dcbw@redhat.com>
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
 */

#include <string.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <nm-utils.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-vpn.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE
#include <nm-vpn-plugin-ui-interface.h>

#include "nm-test-helpers.h"
#include "properties/nm-vpnc.h"
#include "src/nm-vpnc-service.h"

typedef struct {
	const char *name;
	const char *value;
} Item;

static void
item_count_func (const char *key, const char *value, gpointer user_data)
{
	(* (guint32 *) user_data)++;
}

static void
test_items (const char *detail, NMSettingVPN *s_vpn, Item *test_items, gboolean secrets)
{
	Item *iter;
	guint32 expected_count = 0, actual_count = 0;
	const char *value;

	for (iter = test_items; iter->name; iter++) {
		if (secrets)
			value = nm_setting_vpn_get_secret (s_vpn, iter->name);
		else
			value = nm_setting_vpn_get_data_item (s_vpn, iter->name);

		if (!iter->value) {
			ASSERT (value == NULL, detail, "unexpected item '%s'", iter->name);
		} else {
			ASSERT (value != NULL, detail, "unexpected missing value for item %s", iter->name);
			ASSERT (strcmp (value, iter->value) == 0, detail, "unexpected value for item %s", iter->name);
			expected_count++;
		}
	}

	if (secrets)
		nm_setting_vpn_foreach_secret (s_vpn, item_count_func, &actual_count);
	else
		nm_setting_vpn_foreach_data_item (s_vpn, item_count_func, &actual_count);

	ASSERT (actual_count == expected_count,
	        detail, "unexpected number of items (got %d, expected %d", actual_count, expected_count);
}


static Item basic_items[] = {
	{ NM_VPNC_KEY_GATEWAY,               "10.20.30.40" },
	{ NM_VPNC_KEY_ID,                    "blahblah" },
	{ NM_VPNC_KEY_SECRET_TYPE,           NULL },
	{ NM_VPNC_KEY_XAUTH_USER,            "bsmith" },
	{ NM_VPNC_KEY_XAUTH_PASSWORD_TYPE,   NM_VPNC_PW_TYPE_SAVE },
	{ NM_VPNC_KEY_DOMAIN,                "COMPANY" },
	{ NM_VPNC_KEY_DHGROUP,               "2" },
	{ NM_VPNC_KEY_PERFECT_FORWARD,       NULL },
	{ NM_VPNC_KEY_APP_VERSION,           NULL },
	{ NM_VPNC_KEY_SINGLE_DES,            NULL },
	{ NM_VPNC_KEY_NO_ENCRYPTION,         NULL },
	{ NM_VPNC_KEY_NAT_TRAVERSAL_MODE,    NM_VPNC_NATT_MODE_CISCO },
	{ NM_VPNC_KEY_DPD_IDLE_TIMEOUT,      "90" },
	{ NM_VPNC_KEY_CISCO_UDP_ENCAPS_PORT, NULL },
	{ NULL, NULL }
};

static Item basic_secrets[] = {
	{ NM_VPNC_KEY_SECRET,           "my-group-password" },
	{ NM_VPNC_KEY_XAUTH_PASSWORD,   "my-user-password" },
	{ NULL, NULL }
};

static NMConnection *
get_basic_connection (const char *detail,
                      NMVpnPluginUiInterface *plugin,
                      const char *dir,
                      const char *filename)
{
	NMConnection *connection;
	GError *error = NULL;
	char *pcf;

	pcf = g_build_path ("/", dir, filename, NULL);
	ASSERT (pcf != NULL,
	        "basic", "failed to create pcf path");

	connection = nm_vpn_plugin_ui_interface_import (plugin, pcf, &error);
	if (error)
		FAIL ("basic", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "basic", "error importing %s: (unknown)", pcf);

	g_free (pcf);
	return connection;
}

static void
test_basic_import (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingVPN *s_vpn;
	NMIP4Route *route;
	struct in_addr tmp;
	const char *expected_id = "Basic VPN";
	const char *expected_route1_dest = "10.0.0.0";
	const char *expected_route1_gw = "0.0.0.0";
	const char *expected_route2_dest = "172.16.0.0";
	const char *expected_route2_gw = "0.0.0.0";
	const char *value;

	connection = get_basic_connection ("basic-import", plugin, dir, "basic.pcf");
	ASSERT (connection != NULL, "basic-import", "failed to import connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	ASSERT (s_con != NULL,
	        "basic-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "basic-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "basic-import", "unexpected valid UUID");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	ASSERT (s_con != NULL,
	        "basic-import", "missing 'ip4-config' setting");

	ASSERT (nm_setting_ip4_config_get_num_addresses (s_ip4) == 0,
	        "basic-import", "unexpected addresses");

	ASSERT (nm_setting_ip4_config_get_never_default (s_ip4) == TRUE,
	        "basic-import", "never-default unexpectedly FALSE");

	ASSERT (nm_setting_ip4_config_get_method (s_ip4) == NULL,
	        "basic-import", "unexpected IPv4 method");

	ASSERT (nm_setting_ip4_config_get_dhcp_client_id (s_ip4) == NULL,
	        "basic-import", "unexpected valid DHCP client ID");

	ASSERT (nm_setting_ip4_config_get_dhcp_hostname (s_ip4) == NULL,
	        "basic-import", "unexpected valid DHCP hostname");

	ASSERT (nm_setting_ip4_config_get_num_dns_searches (s_ip4) == 0,
	        "basic-import", "unexpected DNS searches");

	ASSERT (nm_setting_ip4_config_get_num_dns (s_ip4) == 0,
	        "basic-import", "unexpected DNS servers");

	ASSERT (nm_setting_ip4_config_get_num_routes (s_ip4) == 2,
	        "basic-import", "unexpected number of routes");

	/* Route #1 */
	route = nm_setting_ip4_config_get_route (s_ip4, 0);
	ASSERT (inet_pton (AF_INET, expected_route1_dest, &tmp) > 0,
	        "basic-import", "couldn't convert expected route destination #1");
	ASSERT (nm_ip4_route_get_dest (route) == tmp.s_addr,
	        "basic-import", "unexpected route #1 destination");

	ASSERT (inet_pton (AF_INET, expected_route1_gw, &tmp) > 0,
	        "basic-import", "couldn't convert expected route next hop #1");
	ASSERT (nm_ip4_route_get_next_hop (route) == tmp.s_addr,
	        "basic-import", "unexpected route #1 next hop");

	ASSERT (nm_ip4_route_get_prefix (route) == 8,
	        "basic-import", "unexpected route #1 prefix");
	ASSERT (nm_ip4_route_get_metric (route) == 0,
	        "basic-import", "unexpected route #1 metric");

	/* Route #2 */
	route = nm_setting_ip4_config_get_route (s_ip4, 1);
	ASSERT (inet_pton (AF_INET, expected_route2_dest, &tmp) > 0,
	        "basic-import", "couldn't convert expected route destination #2");
	ASSERT (nm_ip4_route_get_dest (route) == tmp.s_addr,
	        "basic-import", "unexpected route #2 destination");

	ASSERT (inet_pton (AF_INET, expected_route2_gw, &tmp) > 0,
	        "basic-import", "couldn't convert expected route next hop #2");
	ASSERT (nm_ip4_route_get_next_hop (route) == tmp.s_addr,
	        "basic-import", "unexpected route #2 next hop");

	ASSERT (nm_ip4_route_get_prefix (route) == 16,
	        "basic-import", "unexpected route #2 prefix");
	ASSERT (nm_ip4_route_get_metric (route) == 0,
	        "basic-import", "unexpected route #2 metric");

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	ASSERT (s_vpn != NULL,
	        "basic-import", "missing 'vpn' setting");

	/* Data items */
	test_items ("basic-import-data", s_vpn, &basic_items[0], FALSE);

	/* Secrets */
	test_items ("basic-import-secrets", s_vpn, &basic_secrets[0], TRUE);

	g_object_unref (connection);
}

static void
save_one_key (const char *key, const char *value, gpointer user_data)
{
	GSList **list = user_data;

	*list = g_slist_append (*list, g_strdup (key));
}

static void
remove_secrets (NMConnection *connection)
{
	NMSettingVPN *s_vpn;
	GSList *keys = NULL, *iter;

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	if (!s_vpn)
		return;

	nm_setting_vpn_foreach_secret (s_vpn, save_one_key, &keys);
	for (iter = keys; iter; iter = g_slist_next (iter))
		nm_setting_vpn_remove_secret (s_vpn, (const char *) iter->data);

	g_slist_foreach (keys, (GFunc) g_free, NULL);
	g_slist_free (keys);
}

#define EXPORTED_NAME "basic-export-test.pcf"
static void
test_basic_export (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;
	int ret;

	connection = get_basic_connection ("basic-export", plugin, dir, "basic.pcf");
	ASSERT (connection != NULL, "basic-export", "failed to import connection");

	path = g_build_path ("/", dir, EXPORTED_NAME, NULL);
	success = nm_vpn_plugin_ui_interface_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("basic-export", "export failed with missing error");
		else
			FAIL ("basic-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("basic-export", plugin, dir, EXPORTED_NAME);
	ret = unlink (path);
	ASSERT (connection != NULL, "basic-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "basic-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}


static void
test_everything_via_vpn (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	GError *error = NULL;
	char *pcf;
	const char *expected_id = "All your traffic are belong to VPN";
	const char *value;

	pcf = g_build_path ("/", dir, "everything-via-vpn.pcf", NULL);
	ASSERT (pcf != NULL,
	        "everything-via-vpn", "failed to create pcf path");

	connection = nm_vpn_plugin_ui_interface_import (plugin, pcf, &error);
	if (error)
		FAIL ("everything-via-vpn", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "everything-via-vpn", "error importing %s: (unknown)", pcf);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	ASSERT (s_con != NULL,
	        "everything-via-vpn", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "everything-via-vpn", "unexpected connection ID");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	ASSERT (s_con != NULL,
	        "everything-via-vpn", "missing 'ip4-config' setting");

	ASSERT (nm_setting_ip4_config_get_never_default (s_ip4) == FALSE,
	        "everything-via-vpn", "never-default unexpectedly FALSE");

	ASSERT (nm_setting_ip4_config_get_num_routes (s_ip4) == 0,
	        "everything-via-vpn", "unexpected number of routes");

	g_free (pcf);
}

static void
test_no_natt (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	GError *error = NULL;
	char *pcf;
	const char *expected_id = "No NAT Traversal";
	const char *value;

	pcf = g_build_path ("/", dir, "no-natt.pcf", NULL);
	ASSERT (pcf != NULL,
	        "no-natt", "failed to create pcf path");

	connection = nm_vpn_plugin_ui_interface_import (plugin, pcf, &error);
	if (error)
		FAIL ("no-natt", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "no-natt", "error importing %s: (unknown)", pcf);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	ASSERT (s_con != NULL,
	        "no-natt", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "no-natt", "unexpected connection ID");

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	ASSERT (s_vpn != NULL,
	        "no-natt", "missing 'vpn' setting");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	ASSERT (value != NULL,
	        "no-natt", "unexpected missing value for item %s", NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	ASSERT (strcmp (value, NM_VPNC_NATT_MODE_NONE) == 0,
	        "no-natt", "unexpected value for item %s", NM_VPNC_KEY_NAT_TRAVERSAL_MODE);

	g_free (pcf);
}

static void
test_always_ask (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	GError *error = NULL;
	char *pcf;
	const char *expected_id = "Always Ask For Password";
	const char *value;

	pcf = g_build_path ("/", dir, "always-ask.pcf", NULL);
	ASSERT (pcf != NULL,
	        "always-ask", "failed to create pcf path");

	connection = nm_vpn_plugin_ui_interface_import (plugin, pcf, &error);
	if (error)
		FAIL ("always-ask", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "always-ask", "error importing %s: (unknown)", pcf);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	ASSERT (s_con != NULL,
	        "always-ask", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "always-ask", "unexpected connection ID");

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	ASSERT (s_vpn != NULL,
	        "always-ask", "missing 'vpn' setting");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD_TYPE);
	ASSERT (value == NULL,
	        "always-ask", "unexpected value for item %s", NM_VPNC_KEY_XAUTH_PASSWORD_TYPE);

	g_free (pcf);
}

int main (int argc, char **argv)
{
	GError *error = NULL;
	DBusGConnection *bus;
	char *basename;
	NMVpnPluginUiInterface *plugin = NULL;

	if (argc != 2)
		FAIL ("args", "usage: %s <pcf path>", argv[0]);

	g_type_init ();
	bus = dbus_g_bus_get (DBUS_BUS_SESSION, NULL);

	if (!nm_utils_init (&error))
		FAIL ("nm-utils-init", "failed to initialize libnm-util: %s", error->message);

	plugin = nm_vpn_plugin_ui_factory (&error);
	if (error)
		FAIL ("plugin-init", "failed to initialize UI plugin: %s", error->message);
	ASSERT (plugin != NULL,
	        "plugin-init", "failed to initialize UI plugin");

	/* The tests */
	test_basic_import (plugin, argv[1]);
	test_everything_via_vpn (plugin, argv[1]);
	test_no_natt (plugin, argv[1]);
	test_always_ask (plugin, argv[1]);

	test_basic_export (plugin, argv[1]);

	g_object_unref (plugin);

	basename = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", basename);
	g_free (basename);
	return 0;
}


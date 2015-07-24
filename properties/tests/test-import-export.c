/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2009 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2009 - 2011 Red Hat, Inc.
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
#include <locale.h>

#include <NetworkManager.h>
#include <nm-utils.h>
#include <nm-setting-ip4-config.h>

#include <nm-vpn-editor-plugin.h>

#include "../../nm-test-helpers.h"
#include "../../properties/nm-vpnc.h"
#include "../../src/nm-vpnc-service-defines.h"
#include "../../properties/nm-vpnc-helper.h"

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
test_items (const char *detail, NMSettingVpn *s_vpn, const Item *items, gboolean secrets)
{
	const Item *iter;
	guint32 expected_count = 0, actual_count = 0;
	const char *value;

	for (iter = items; iter->name; iter++) {
		if (secrets)
			value = nm_setting_vpn_get_secret (s_vpn, iter->name);
		else
			value = nm_setting_vpn_get_data_item (s_vpn, iter->name);

		if (!iter->value) {
			ASSERT (value == NULL, detail, "unexpected item '%s'", iter->name);
		} else {
			ASSERT (value != NULL, detail, "unexpected missing value for item %s", iter->name);
			ASSERT (strcmp (value, iter->value) == 0, detail, "unexpected value for item %s (%s != %s",
			        iter->name, value, iter->value);
			expected_count++;
		}
	}

	if (secrets)
		nm_setting_vpn_foreach_secret (s_vpn, item_count_func, &actual_count);
	else
		nm_setting_vpn_foreach_data_item (s_vpn, item_count_func, &actual_count);

	ASSERT (actual_count == expected_count,
	        detail, "unexpected number of items (got %d, expected %d)", actual_count, expected_count);
}


static const Item basic_items[] = {
	{ NM_VPNC_KEY_GATEWAY,               "10.20.30.40" },
	{ NM_VPNC_KEY_ID,                    "blahblah" },
	{ NM_VPNC_KEY_SECRET_TYPE,           NM_VPNC_PW_TYPE_SAVE },
	{ NM_VPNC_KEY_XAUTH_USER,            "bsmith" },
	{ NM_VPNC_KEY_XAUTH_PASSWORD_TYPE,   NM_VPNC_PW_TYPE_SAVE },
	{ NM_VPNC_KEY_DOMAIN,                "COMPANY" },
	{ NM_VPNC_KEY_DHGROUP,               "dh2" },
	{ NM_VPNC_KEY_PERFECT_FORWARD,       NULL },
	{ NM_VPNC_KEY_APP_VERSION,           NULL },
	{ NM_VPNC_KEY_SINGLE_DES,            NULL },
	{ NM_VPNC_KEY_NO_ENCRYPTION,         NULL },
	{ NM_VPNC_KEY_NAT_TRAVERSAL_MODE,    NM_VPNC_NATT_MODE_CISCO },
	{ NM_VPNC_KEY_DPD_IDLE_TIMEOUT,      "90" },
	{ NM_VPNC_KEY_CISCO_UDP_ENCAPS_PORT, NULL },
	{ NM_VPNC_KEY_LOCAL_PORT,            "500" },
	{ NM_VPNC_KEY_SECRET"-flags",        "1" },
	{ NM_VPNC_KEY_XAUTH_PASSWORD"-flags","1" },
	{ NULL, NULL }
};

static Item basic_secrets[] = {
	{ NM_VPNC_KEY_SECRET,           "my-group-password" },
	{ NM_VPNC_KEY_XAUTH_PASSWORD,   "my-user-password" },
	{ NULL, NULL }
};

static NMConnection *
get_basic_connection (const char *detail,
                      NMVpnEditorPlugin *plugin,
                      const char *dir,
                      const char *filename)
{
	NMConnection *connection;
	GError *error = NULL;
	char *pcf;

	pcf = g_build_path ("/", dir, filename, NULL);
	ASSERT (pcf != NULL,
	        "basic", "failed to create pcf path");

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	if (error)
		FAIL ("basic", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "basic", "error importing %s: (unknown)", pcf);

	g_free (pcf);
	return connection;
}

static void
test_basic_import (NMVpnEditorPlugin *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingVpn *s_vpn;
	NMIPRoute *route;
	const char *expected_id = "Basic VPN";
	const char *expected_route1_dest = "10.0.0.0";
	const char *expected_route2_dest = "172.16.0.0";

	connection = get_basic_connection ("basic-import", plugin, dir, "basic.pcf");
	ASSERT (connection != NULL, "basic-import", "failed to import connection");

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "basic-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "basic-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "basic-import", "unexpected valid UUID");

	/* IP4 setting */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "basic-import", "missing 'ip4-config' setting");

	ASSERT (nm_setting_ip_config_get_num_addresses (s_ip4) == 0,
	        "basic-import", "unexpected addresses");

	ASSERT (nm_setting_ip_config_get_never_default (s_ip4) == TRUE,
	        "basic-import", "never-default unexpectedly FALSE");

	ASSERT (nm_setting_ip_config_get_method (s_ip4) == NULL,
	        "basic-import", "unexpected IPv4 method");

	ASSERT (nm_setting_ip4_config_get_dhcp_client_id ((NMSettingIP4Config *) s_ip4) == NULL,
	        "basic-import", "unexpected valid DHCP client ID");

	ASSERT (nm_setting_ip_config_get_dhcp_hostname (s_ip4) == NULL,
	        "basic-import", "unexpected valid DHCP hostname");

	ASSERT (nm_setting_ip_config_get_num_dns_searches (s_ip4) == 0,
	        "basic-import", "unexpected DNS searches");

	ASSERT (nm_setting_ip_config_get_num_dns (s_ip4) == 0,
	        "basic-import", "unexpected DNS servers");

	ASSERT (nm_setting_ip_config_get_num_routes (s_ip4) == 2,
	        "basic-import", "unexpected number of routes");

	/* Route #1 */
	route = nm_setting_ip_config_get_route (s_ip4, 0);
	ASSERT (strcmp (nm_ip_route_get_dest (route), expected_route1_dest) == 0,
	        "basic-import", "unexpected route #1 destination");
	ASSERT (nm_ip_route_get_next_hop (route) == NULL,
	        "basic-import", "unexpected route #1 next hop");
	ASSERT (nm_ip_route_get_prefix (route) == 8,
	        "basic-import", "unexpected route #1 prefix");
	ASSERT (nm_ip_route_get_metric (route) == -1,
	        "basic-import", "unexpected route #1 metric");

	/* Route #2 */
	route = nm_setting_ip_config_get_route (s_ip4, 1);
	ASSERT (strcmp (nm_ip_route_get_dest (route), expected_route2_dest) == 0,
	        "basic-import", "unexpected route #2 destination");
	ASSERT (nm_ip_route_get_next_hop (route) == NULL,
	        "basic-import", "unexpected route #2 next hop");
	ASSERT (nm_ip_route_get_prefix (route) == 16,
	        "basic-import", "unexpected route #2 prefix");
	ASSERT (nm_ip_route_get_metric (route) == -1,
	        "basic-import", "unexpected route #2 metric");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "basic-import", "missing 'vpn' setting");

	/* Data items */
	test_items ("basic-import-data", s_vpn, &basic_items[0], FALSE);

	/* Secrets */
	test_items ("basic-import-secrets", s_vpn, &basic_secrets[0], TRUE);

	g_object_unref (connection);
}

static void
remove_user_password (NMConnection *connection)
{
	NMSettingVpn *s_vpn;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn)
		return;

	if (nm_setting_vpn_get_secret (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD))
		nm_setting_vpn_remove_secret (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD);
}

#define BASIC_EXPORTED_NAME "basic-export-test.pcf"
static void
test_basic_export (NMVpnEditorPlugin *plugin, const char *dir, const char *tmpdir)
{
	NMConnection *connection;
	NMConnection *reimported;
	NMSettingVpn *s_vpn;
	char *path;
	gboolean success;
	GError *error = NULL;
	int ret;

	connection = get_basic_connection ("basic-export", plugin, dir, "basic.pcf");
	ASSERT (connection != NULL, "basic-export", "failed to import connection");

	path = g_build_path ("/", tmpdir, BASIC_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("basic-export", "export failed with missing error");
		else
			FAIL ("basic-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("basic-export", plugin, tmpdir, BASIC_EXPORTED_NAME);
	ret = unlink (path);
	ASSERT (connection != NULL, "basic-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_user_password (connection);

	/* Since we don't export the user password, but the original connection
	 * had one, we need to add secret flags to the re-imported connection.
	 */
	s_vpn = nm_connection_get_setting_vpn (reimported);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn),
	                             NM_VPNC_KEY_SECRET,
	                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
	                             NULL);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "basic-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

#define NAT_EXPORTED_NAME "nat-export-test.pcf"
static void
test_nat_export (NMVpnEditorPlugin *plugin,
                 const char *dir,
                 const char *tmpdir,
                 const char *nat_mode)
{
	NMConnection *connection;
	NMSettingVpn *s_vpn;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;
	int ret;

	connection = get_basic_connection ("nat-export", plugin, dir, "basic.pcf");
	ASSERT (connection != NULL, "nat-export", "failed to import connection");

	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL, "nat-export", "imported connection had no VPN setting");

	nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE, nat_mode);

	path = g_build_path ("/", tmpdir, NAT_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("nat-export", "export failed with missing error");
		else
			FAIL ("nat-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("nat-export", plugin, tmpdir, NAT_EXPORTED_NAME);
	ret = unlink (path);
	ASSERT (connection != NULL, "nat-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_user_password (connection);

	/* Since we don't export the user password, but the original connection
	 * had one, we need to add secret flags to the re-imported connection.
	 */
	s_vpn = nm_connection_get_setting_vpn (reimported);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn),
	                             NM_VPNC_KEY_SECRET,
	                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
	                             NULL);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "nat-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_everything_via_vpn (NMVpnEditorPlugin *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	char *pcf;
	const char *expected_id = "All your traffic are belong to VPN";

	pcf = g_build_path ("/", dir, "everything-via-vpn.pcf", NULL);
	ASSERT (pcf != NULL,
	        "everything-via-vpn", "failed to create pcf path");

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	if (error)
		FAIL ("everything-via-vpn", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "everything-via-vpn", "error importing %s: (unknown)", pcf);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "everything-via-vpn", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "everything-via-vpn", "unexpected connection ID");

	/* IP4 setting */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "everything-via-vpn", "missing 'ip4-config' setting");

	ASSERT (nm_setting_ip_config_get_never_default (s_ip4) == FALSE,
	        "everything-via-vpn", "never-default unexpectedly FALSE");

	ASSERT (nm_setting_ip_config_get_num_routes (s_ip4) == 0,
	        "everything-via-vpn", "unexpected number of routes");

	g_free (pcf);
}

static void
test_no_natt (NMVpnEditorPlugin *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	GError *error = NULL;
	char *pcf;
	const char *expected_id = "No NAT Traversal";
	const char *value;

	pcf = g_build_path ("/", dir, "no-natt.pcf", NULL);
	ASSERT (pcf != NULL,
	        "no-natt", "failed to create pcf path");

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	if (error)
		FAIL ("no-natt", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "no-natt", "error importing %s: (unknown)", pcf);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "no-natt", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "no-natt", "unexpected connection ID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
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
test_nat_cisco (NMVpnEditorPlugin *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	GError *error = NULL;
	char *pcf;
	const char *expected_id = "NAT-Cisco";
	const char *value;

	pcf = g_build_path ("/", dir, "nat-cisco.pcf", NULL);
	ASSERT (pcf != NULL,
	        "nat-cisco", "failed to create pcf path");

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	if (error)
		FAIL ("nat-cisco", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "nat-cisco", "error importing %s: (unknown)", pcf);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "nat-cisco", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "nat-cisco", "unexpected connection ID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "nat-cisco", "missing 'vpn' setting");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	ASSERT (value != NULL,
	        "nat-cisco", "unexpected missing value for item %s", NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	ASSERT (strcmp (value, NM_VPNC_NATT_MODE_CISCO) == 0,
	        "nat-cisco", "unexpected value for item %s", NM_VPNC_KEY_NAT_TRAVERSAL_MODE);

	g_free (pcf);
}

static void
test_nat_natt (NMVpnEditorPlugin *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	GError *error = NULL;
	char *pcf;
	const char *expected_id = "NAT-T";
	const char *value;

	pcf = g_build_path ("/", dir, "natt.pcf", NULL);
	ASSERT (pcf != NULL,
	        "natt", "failed to create pcf path");

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	if (error)
		FAIL ("natt", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "natt", "error importing %s: (unknown)", pcf);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "natt", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "natt", "unexpected connection ID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "natt", "missing 'vpn' setting");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	ASSERT (value != NULL,
	        "natt", "unexpected missing value for item %s", NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	ASSERT (strcmp (value, NM_VPNC_NATT_MODE_NATT) == 0,
	        "natt", "unexpected value for item %s", NM_VPNC_KEY_NAT_TRAVERSAL_MODE);

	g_free (pcf);
}

static void
test_nat_force_natt (NMVpnEditorPlugin *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	GError *error = NULL;
	char *pcf;
	const char *expected_id = "Force NAT-T";
	const char *value;

	pcf = g_build_path ("/", dir, "force-natt.pcf", NULL);
	ASSERT (pcf != NULL,
	        "force-natt", "failed to create pcf path");

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	if (error)
		FAIL ("force-natt", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "force-natt", "error importing %s: (unknown)", pcf);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "force-natt", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "force-natt", "unexpected connection ID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "force-natt", "missing 'vpn' setting");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	ASSERT (value != NULL,
	        "force-natt", "unexpected missing value for item %s", NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	ASSERT (strcmp (value, NM_VPNC_NATT_MODE_NATT_ALWAYS) == 0,
	        "force-natt", "unexpected value for item %s", NM_VPNC_KEY_NAT_TRAVERSAL_MODE);

	g_free (pcf);
}

static void
test_always_ask (NMVpnEditorPlugin *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	GError *error = NULL;
	char *pcf;
	const char *expected_id = "Always Ask For Password";
	const char *value;

	pcf = g_build_path ("/", dir, "always-ask.pcf", NULL);
	ASSERT (pcf != NULL,
	        "always-ask", "failed to create pcf path");

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	if (error)
		FAIL ("always-ask", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "always-ask", "error importing %s: (unknown)", pcf);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "always-ask", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "always-ask", "unexpected connection ID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "always-ask", "missing 'vpn' setting");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD_TYPE);
	ASSERT (value == NULL,
	        "always-ask", "unexpected value for item %s", NM_VPNC_KEY_XAUTH_PASSWORD_TYPE);

	g_free (pcf);
}

static void
test_non_utf8_import (NMVpnEditorPlugin *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *expected_id = "Att äta en ko";
	const char *charset = NULL;

	/* Change charset to ISO-8859-15 to match iso885915.pcf */
	g_get_charset (&charset);
	setlocale (LC_ALL, "de_DE@euro");
	connection = get_basic_connection ("non-utf8-import", plugin, dir, "iso885915.pcf");
	setlocale (LC_ALL, charset);

	ASSERT (connection != NULL, "non-utf8-import", "failed to import connection");

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "non-utf8-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "non-utf8-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "non-utf8-import", "unexpected valid UUID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "non-utf8-import", "missing 'vpn' setting");

	g_object_unref (connection);
}

static void
test_legacy_ike_port_0_import (NMVpnEditorPlugin *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	GError *error = NULL;
	char *pcf;
	const char *expected_id = "Use Legacy IKE Port (i.e. dynamic)";
	const char *value;

	pcf = g_build_path ("/", dir, "use-legacy-ike-port-0.pcf", NULL);
	ASSERT (pcf != NULL,
	        "use-legacy-ike-port-0", "failed to create pcf path");

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	if (error)
		FAIL ("", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "use-legacy-ike-port-0", "error importing %s: (unknown)", pcf);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "use-legacy-ike-port-0", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "use-legacy-ike-port-0", "unexpected connection ID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "use-legacy-ike-port-0", "missing 'vpn' setting");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_LOCAL_PORT);
	ASSERT (value == NULL || strcmp (value, "0") == 0,
	        "use-legacy-ike-port-0", "item %s should not be present or should be 0", NM_VPNC_KEY_LOCAL_PORT);

	g_free (pcf);
}

static void
test_legacy_ike_port_1_import (NMVpnEditorPlugin *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	GError *error = NULL;
	char *pcf;
	const char *expected_id = "Don't use Legacy IKE Port (500)";
	const char *value;

	pcf = g_build_path ("/", dir, "use-legacy-ike-port-1.pcf", NULL);
	ASSERT (pcf != NULL,
	        "use-legacy-ike-port-1", "failed to create pcf path");

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	if (error)
		FAIL ("", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "use-legacy-ike-port-1", "error importing %s: (unknown)", pcf);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "use-legacy-ike-port-1", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "use-legacy-ike-port-1", "unexpected connection ID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "use-legacy-ike-port-1", "missing 'vpn' setting");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_LOCAL_PORT);
	ASSERT (value != NULL,
	        "use-legacy-ike-port-1", "unexpected missing value for item %s", NM_VPNC_KEY_LOCAL_PORT);
	ASSERT (strcmp (value, "500") == 0,
	        "use-legacy-ike-port-1", "unexpected value for item %s", NM_VPNC_KEY_LOCAL_PORT);

	g_free (pcf);
}

static void
test_empty_keyfile_string_null (const char *dir)
{
	char *pcf, *val;
	GError *error = NULL;
	GKeyFile *kf;
	gboolean success;

	pcf = g_build_path ("/", dir, "basic.pcf", NULL);
	g_assert (pcf);

	kf = g_key_file_new ();
	success = g_key_file_load_from_file (kf, pcf, 0, &error);
	g_assert_no_error (error);
	g_assert (success);

	val = key_file_get_string_helper (kf, "main", "ISPCommand", NULL);
	g_assert (val == NULL);

	g_free (pcf);
	g_key_file_free (kf);
}

int main (int argc, char **argv)
{
	GError *error = NULL;
	DBusGConnection *bus;
	char *basename;
	NMVpnEditorPlugin *plugin = NULL;

	if (argc != 3)
		FAIL ("args", "usage: %s <pcf path> <tmp path>", argv[0]);

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	bus = dbus_g_bus_get (DBUS_BUS_SESSION, NULL);

	plugin = nm_vpn_editor_plugin_factory (&error);
	if (error)
		FAIL ("plugin-init", "failed to initialize UI plugin: %s", error->message);
	ASSERT (plugin != NULL,
	        "plugin-init", "failed to initialize UI plugin");

	/* The tests */
	test_basic_import (plugin, argv[1]);
	test_everything_via_vpn (plugin, argv[1]);
	test_no_natt (plugin, argv[1]);
	test_nat_cisco (plugin, argv[1]);
	test_nat_natt (plugin, argv[1]);
	test_nat_force_natt (plugin, argv[1]);
	test_always_ask (plugin, argv[1]);
	test_non_utf8_import (plugin, argv[1]);
	test_legacy_ike_port_0_import (plugin, argv[1]);
	test_legacy_ike_port_1_import (plugin, argv[1]);

	test_basic_export (plugin, argv[1], argv[2]);
	test_nat_export (plugin, argv[1], argv[2], NM_VPNC_NATT_MODE_CISCO);
	test_nat_export (plugin, argv[1], argv[2], NM_VPNC_NATT_MODE_NATT);
	test_nat_export (plugin, argv[1], argv[2], NM_VPNC_NATT_MODE_NATT_ALWAYS);

	test_empty_keyfile_string_null (argv[1]);

	g_object_unref (plugin);

	basename = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", basename);
	g_free (basename);
	return 0;
}


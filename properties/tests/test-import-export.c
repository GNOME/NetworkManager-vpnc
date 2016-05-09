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

#include "nm-default.h"

#include <string.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <locale.h>

#include "nm-vpnc.h"
#include "nm-vpnc-helper.h"

#include "nm-utils/nm-test-utils.h"

#define SRCDIR TEST_SRCDIR"/pcf"
#define TMPDIR TEST_BUILDDIR"/pcf-tmp"

/*****************************************************************************/

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

		if (!iter->value)
			g_assert (!value);
		else {
			g_assert (value);
			g_assert_cmpstr (value, ==, iter->value);
			expected_count++;
		}
	}

	if (secrets)
		nm_setting_vpn_foreach_secret (s_vpn, item_count_func, &actual_count);
	else
		nm_setting_vpn_foreach_data_item (s_vpn, item_count_func, &actual_count);

	g_assert_cmpint (actual_count, ==, expected_count);
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

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	nmtst_assert_success (connection, error);

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

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	g_assert (!nm_setting_connection_get_uuid (s_con));

	/* IP4 setting */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);

	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 0);

	g_assert (nm_setting_ip_config_get_never_default (s_ip4));

	g_assert (!nm_setting_ip_config_get_method (s_ip4));
	g_assert (!nm_setting_ip4_config_get_dhcp_client_id ((NMSettingIP4Config *) s_ip4));
	g_assert (!nm_setting_ip_config_get_dhcp_hostname (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns_searches (s_ip4), ==, 0);
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 0);
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 2);

	/* Route #1 */
	route = nm_setting_ip_config_get_route (s_ip4, 0);
	g_assert_cmpstr (nm_ip_route_get_dest (route), ==, expected_route1_dest);
	g_assert (!nm_ip_route_get_next_hop (route));
	g_assert_cmpint (nm_ip_route_get_prefix (route), ==, 8);
	g_assert_cmpint (nm_ip_route_get_metric (route), ==, -1);

	/* Route #2 */
	route = nm_setting_ip_config_get_route (s_ip4, 1);
	g_assert_cmpstr (nm_ip_route_get_dest (route), ==, expected_route2_dest);
	g_assert (!nm_ip_route_get_next_hop (route));
	g_assert_cmpint (nm_ip_route_get_prefix (route), ==, 16);
	g_assert_cmpint (nm_ip_route_get_metric (route), ==, -1);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

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

	path = g_build_path ("/", tmpdir, BASIC_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	nmtst_assert_success (success, error);

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("basic-export", plugin, tmpdir, BASIC_EXPORTED_NAME);
	ret = unlink (path);

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

	g_assert (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT));

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

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE, nat_mode);

	path = g_build_path ("/", tmpdir, NAT_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	nmtst_assert_success (success, error);

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("nat-export", plugin, tmpdir, NAT_EXPORTED_NAME);
	ret = unlink (path);

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

	g_assert (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT));

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

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	nmtst_assert_success (connection, error);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* IP4 setting */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert (!nm_setting_ip_config_get_never_default (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 0);

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

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	nmtst_assert_success (connection, error);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	g_assert (value);
	g_assert_cmpstr (value, ==, NM_VPNC_NATT_MODE_NONE);

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

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	nmtst_assert_success (connection, error);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	g_assert (value);
	g_assert_cmpstr (value, ==, NM_VPNC_NATT_MODE_CISCO);

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

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	nmtst_assert_success (connection, error);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	g_assert (value);
	g_assert_cmpstr (value, ==, NM_VPNC_NATT_MODE_NATT);

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

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	nmtst_assert_success (connection, error);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	g_assert (value);
	g_assert_cmpstr (value, ==, NM_VPNC_NATT_MODE_NATT_ALWAYS);

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

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	nmtst_assert_success (connection, error);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD_TYPE);
	g_assert (!value);

	g_free (pcf);
}

static void
test_non_utf8_import (NMVpnEditorPlugin *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *expected_id = "Att äta en ko";
	const char *charset;

	/* Change charset to ISO-8859-15 to match iso885915.pcf */
	charset = setlocale (LC_ALL, NULL);
	setlocale (LC_ALL, "de_DE@euro");
	if (!g_locale_from_utf8 (expected_id, -1, NULL, NULL, NULL)) {
		g_test_skip ("ISO-8859-15 not supported on this system");
		setlocale (LC_ALL, charset);
		return;
	}
	connection = get_basic_connection ("non-utf8-import", plugin, dir, "iso885915.pcf");
	setlocale (LC_ALL, charset);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert (!nm_setting_connection_get_uuid (s_con));

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

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

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	nmtst_assert_success (connection, error);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_LOCAL_PORT);
	g_assert (!value || nm_streq (value, "0"));

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

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	nmtst_assert_success (connection, error);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_LOCAL_PORT);
	g_assert (value);
	g_assert_cmpstr (value, ==, "500");

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

	kf = g_key_file_new ();
	success = g_key_file_load_from_file (kf, pcf, 0, &error);
	g_assert_no_error (error);
	g_assert (success);

	val = key_file_get_string_helper (kf, "main", "ISPCommand", NULL);
	g_assert (val == NULL);

	g_free (pcf);
	g_key_file_free (kf);
}

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	GError *error = NULL;
	int errsv;
	NMVpnEditorPlugin *plugin = NULL;

	nmtst_init (&argc, &argv, TRUE);

	if (mkdir (TMPDIR, 0755) != 0) {
		errsv = errno;
		if (errsv != EEXIST)
			g_error ("failed creating \"%s\": %s", TMPDIR, g_strerror (errsv));
	}

	plugin = nm_vpn_editor_plugin_factory (&error);
	nmtst_assert_success (plugin, error);

	/* The tests */
	test_basic_import (plugin, SRCDIR);
	test_everything_via_vpn (plugin, SRCDIR);
	test_no_natt (plugin, SRCDIR);
	test_nat_cisco (plugin, SRCDIR);
	test_nat_natt (plugin, SRCDIR);
	test_nat_force_natt (plugin, SRCDIR);
	test_always_ask (plugin, SRCDIR);
	test_non_utf8_import (plugin, SRCDIR);
	test_legacy_ike_port_0_import (plugin, SRCDIR);
	test_legacy_ike_port_1_import (plugin, SRCDIR);

	test_basic_export (plugin, SRCDIR, TMPDIR);
	test_nat_export (plugin, SRCDIR, TMPDIR, NM_VPNC_NATT_MODE_CISCO);
	test_nat_export (plugin, SRCDIR, TMPDIR, NM_VPNC_NATT_MODE_NATT);
	test_nat_export (plugin, SRCDIR, TMPDIR, NM_VPNC_NATT_MODE_NATT_ALWAYS);

	test_empty_keyfile_string_null (SRCDIR);

	g_object_unref (plugin);
	return 0;
}


/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * Copyright (C) 2005 David Zeuthen, <davidz@redhat.com>
 * Copyright (C) 2005 - 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2005 - 2012 Red Hat, Inc.
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
 **************************************************************************/

#include "nm-default.h"

#include "nm-vpnc-editor-plugin.h"

#include <gmodule.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "nm-vpnc-helper.h"
#include "nm-utils/nm-vpn-plugin-utils.h"

#define VPNC_PLUGIN_NAME    _("Cisco Compatible VPN (vpnc)")
#define VPNC_PLUGIN_DESC    _("Compatible with various Cisco, Juniper, Netscreen, and Sonicwall IPsec-based VPN gateways.")

#define NM_VPNC_LOCAL_PORT_DEFAULT 500

static void vpnc_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface);

G_DEFINE_TYPE_EXTENDED (VpncEditorPlugin, vpnc_editor_plugin, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR_PLUGIN,
                                               vpnc_editor_plugin_interface_init))

enum {
	PROP_0,
	PROP_NAME,
	PROP_DESC,
	PROP_SERVICE
};

static void
add_routes (NMSettingIPConfig *s_ip4, const char *routelist)
{
	char **substrs;
	unsigned int i;

	substrs = g_strsplit (routelist, " ", 0);
	for (i = 0; substrs[i] != NULL; i++) {
		char *p, *str_route;
		long int prefix = 32;
		NMIPRoute *route;
		GError *error = NULL;

		str_route = g_strdup (substrs[i]);
		p = strchr (str_route, '/');
		if (!p || !(*(p + 1))) {
			g_warning ("Ignoring invalid route '%s'", str_route);
			goto next;
		}

		errno = 0;
		prefix = strtol (p + 1, NULL, 10);
		if (errno || prefix <= 0 || prefix > 32) {
			g_warning ("Ignoring invalid route '%s'", str_route);
			goto next;
		}
		*p = '\0';

		route = nm_ip_route_new (AF_INET, str_route, prefix, NULL, -1, &error);
		if (route) {
			nm_setting_ip_config_add_route (s_ip4, route);
			nm_ip_route_unref (route);
		} else {
			g_warning ("Ignoring invalid route '%s': %s", str_route, error->message);
			g_clear_error (&error);
		}

next:
		g_free (str_route);
	}

	g_strfreev (substrs);
}

static void
decrypt_child_finished_cb (GPid pid, gint status, gpointer userdata)
{
	int *child_status = (gint *) userdata;

	*child_status = status;
}

static gboolean
child_stdout_data_cb (GIOChannel *source, GIOCondition condition, gpointer userdata)
{
	char *str;
	char **output = (char **) userdata;

	if (*output || !(condition & (G_IO_IN | G_IO_ERR)))
		return TRUE;

	if (g_io_channel_read_line (source, &str, NULL, NULL, NULL) == G_IO_STATUS_NORMAL) {
		int len;

		len = strlen (str);
		if (len > 0) {
			/* remove terminating newline */
			*output = g_strchomp (str);
		} else
			g_free (str);
	}
	return TRUE;
}

static char *
decrypt_cisco_key (const char* enc_key)
{
	int child_stdout, child_status;
	GPid child_pid;
	guint32 ioid;
	char *key = NULL;
	GIOChannel *channel;
	const char **decrypt_path;
	GError *error = NULL;

	const char *decrypt_possible_paths[] = {
		"/usr/lib/vpnc/cisco-decrypt",
		"/usr/bin/cisco-decrypt",
		NULL
	};

	const char *argv[] = {
		NULL, /* The path we figure out later. */
		enc_key, /* The key in encrypted form */
		NULL
	};

	/* Find the binary. */
	decrypt_path = decrypt_possible_paths;
	while (*decrypt_path != NULL){
		if (g_file_test (*decrypt_path, G_FILE_TEST_EXISTS))
			break;
		++decrypt_path;
	}

	if (*decrypt_path == NULL){
		g_warning ("Couldn't find cisco-decrypt.\n");
		return NULL;
	}

	/* Now that we know where it is, we call the decrypter. */
	argv[0] = *decrypt_path;
	child_status = -1;

	if (!g_spawn_async_with_pipes ("/", /* working directory */
	                               (gchar **) argv, /* argv */
	                               NULL , /* envp */
	                               G_SPAWN_DO_NOT_REAP_CHILD, /* flags */
	                               NULL, /* child setup */
	                               NULL, /* user data */
	                               &child_pid, /* child pid */
	                               NULL, /* child stdin */
	                               &child_stdout, /* child stdout */
	                               NULL, /* child stderr */
	                               &error)) { /* error */
		/* The child did not spawn */
		g_warning ("Error processing password: %s", error ? error->message : "(none)");
		if (error)
			g_error_free (error);
		return NULL;
	}

	g_child_watch_add (child_pid, decrypt_child_finished_cb, (gpointer) &child_status);

	/* Grab child output and wait for it to exit */
	channel = g_io_channel_unix_new (child_stdout);
	g_io_channel_set_encoding (channel, NULL, NULL);
	ioid = g_io_add_watch (channel, G_IO_IN | G_IO_ERR, child_stdout_data_cb, &key);

	while (child_status == -1) /* Wait until the child has finished. */
		g_main_context_iteration (NULL, TRUE);

	g_source_remove (ioid);
	g_io_channel_shutdown (channel, TRUE, NULL);
	g_io_channel_unref (channel);

	return key;
}

typedef enum {
	NM_VPNC_IMPORT_EXPORT_ERROR_UNKNOWN = 0,
	NM_VPNC_IMPORT_EXPORT_ERROR_NOT_VPNC,
	NM_VPNC_IMPORT_EXPORT_ERROR_BAD_DATA,
} NMVpncImportError;

#define NM_VPNC_IMPORT_EXPORT_ERROR nm_vpnc_import_export_error_quark ()

static GQuark
nm_vpnc_import_export_error_quark (void)
{
	static GQuark quark = 0;

	if (G_UNLIKELY (quark == 0))
		quark = g_quark_from_static_string ("nm-vpnc-import-export-error-quark");
	return quark;
}

static NMConnection *
import (NMVpnEditorPlugin *plugin, const char *path, GError **error)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;
	GKeyFile *keyfile;
	char *buf;
	gboolean bool_value;
	NMSettingIPConfig *s_ip4;
	gint val;
	gboolean found;

	keyfile = g_key_file_new ();
	if (!g_key_file_load_from_file (keyfile, path, 0, error))
		goto error;

	connection = nm_simple_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_VPNC, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	/* Interface Name */
	buf = key_file_get_string_helper (keyfile, "main", "InterfaceName", error);
	if (buf) {
		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_INTERFACE_NAME, buf, NULL);
		g_free (buf);
	}
	if (*error)
		goto error;

	/* Gateway */
	buf = key_file_get_string_helper (keyfile, "main", "Host", error);
	if (buf) {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_GATEWAY, buf);
		g_free (buf);
	} else {
		g_set_error (error,
		             NM_VPNC_IMPORT_EXPORT_ERROR,
		             NM_VPNC_IMPORT_EXPORT_ERROR_NOT_VPNC,
		             "does not look like a %s VPN connection (no Host)",
		             VPNC_PLUGIN_NAME);
	}
	if (*error)
		goto error;

	/* Group name */
	buf = key_file_get_string_helper (keyfile, "main", "GroupName", error);
	if (buf) {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_ID, buf);
		g_free (buf);
	} else {
		g_set_error (error,
		             NM_VPNC_IMPORT_EXPORT_ERROR,
		             NM_VPNC_IMPORT_EXPORT_ERROR_BAD_DATA,
		             "does not look like a %s VPN connection (no GroupName)",
		             VPNC_PLUGIN_NAME);
	}
	if (*error)
		goto error;

	/* Optional settings */

	/* Connection name */
	buf = key_file_get_string_helper (keyfile, "main", "Description", error);
	if (*error)
		goto error;
	if (buf) {
		g_object_set (s_con, NM_SETTING_CONNECTION_ID, buf, NULL);
		g_free (buf);
	}

	buf = key_file_get_string_helper (keyfile, "main", "Username", error);
	if (*error)
		goto error;
	if (buf) {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER, buf);
		g_free (buf);
	}

	buf = key_file_get_string_helper (keyfile, "main", "UserPassword", error);
	if (*error)
		goto error;
	if (buf) {
		nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD, buf);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn),
		                             NM_VPNC_KEY_XAUTH_PASSWORD,
		                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
		                             NULL);
		g_free (buf);
	}

	bool_value = key_file_get_boolean_helper (keyfile, "main", "SaveUserPassword", error);
	if (*error)
		goto error;
	flags = NM_SETTING_SECRET_FLAG_AGENT_OWNED;
	if (bool_value) {
		nm_setting_vpn_add_data_item (s_vpn,
		                              NM_VPNC_KEY_XAUTH_PASSWORD_TYPE,
		                              NM_VPNC_PW_TYPE_SAVE);
	} else {
		flags |= NM_SETTING_SECRET_FLAG_NOT_SAVED;
	}
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_VPNC_KEY_XAUTH_PASSWORD, flags, NULL);

	buf = key_file_get_string_helper (keyfile, "main", "GroupPwd", error);
	if (*error)
		goto error;
	if (buf) {
		nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_SECRET, buf);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn),
		                             NM_VPNC_KEY_SECRET,
		                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
		                             NULL);
		g_free (buf);
	} else {
		/* Handle encrypted passwords */
		buf = key_file_get_string_helper (keyfile, "main", "enc_GroupPwd", error);
		if (*error)
			goto error;
		if (buf) {
			char *decrypted;

			decrypted = decrypt_cisco_key (buf);
			if (decrypted) {
				nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_SECRET, decrypted);
				memset (decrypted, 0, strlen (decrypted));
				g_free (decrypted);

				nm_setting_set_secret_flags (NM_SETTING (s_vpn),
				                             NM_VPNC_KEY_SECRET,
				                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
				                             NULL);
			}
			g_free (buf);
		}
	}

	/* Group Password Flags */
	if (key_file_has_key_helper (keyfile, "main", "X-NM-SaveGroupPassword")) {
		flags = NM_SETTING_SECRET_FLAG_AGENT_OWNED;

		bool_value = key_file_get_boolean_helper (keyfile, "main", "X-NM-SaveGroupPassword", error);
		if (bool_value) {
			nm_setting_vpn_add_data_item (s_vpn,
			                              NM_VPNC_KEY_SECRET_TYPE,
			                              NM_VPNC_PW_TYPE_SAVE);
		} else {
			flags |= NM_SETTING_SECRET_FLAG_NOT_SAVED;
		}

		nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_VPNC_KEY_SECRET, flags, NULL);
	} else {
		if (*error)
			goto error;
		/* If the key isn't present, assume "saved" */
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_SECRET_TYPE, NM_VPNC_PW_TYPE_SAVE);
	}

	buf = key_file_get_string_helper (keyfile, "main", "NTDomain", error);
	if (*error)
		goto error;
	if (buf) {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DOMAIN, buf);
		g_free (buf);
	}

	bool_value = key_file_get_boolean_helper (keyfile, "main", "SingleDES", error);
	if (*error)
		goto error;
	if (bool_value)
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_SINGLE_DES, "yes");

	/* Disable all NAT Traversal if explicit EnableNat=0 exists, otherwise
	 * default to NAT-T which is newer and standardized.  If EnableNat=1, then
	 * use Cisco-UDP like always; but if the key "X-NM-Use-NAT-T" is set, then
	 * use NAT-T.  If the key "X-NM-Force-NAT-T" is set then force NAT-T always
	 * on.  See vpnc documentation for more information on what the different
	 * NAT modes are.
	 */
	nm_setting_vpn_add_data_item (s_vpn,
	                              NM_VPNC_KEY_NAT_TRAVERSAL_MODE,
	                              NM_VPNC_NATT_MODE_CISCO);

	bool_value = key_file_get_boolean_helper (keyfile, "main", "EnableNat", error);
	if (*error)
		goto error;
	if (bool_value) {
		gboolean natt = FALSE;
		gboolean force_natt = FALSE;

		natt = key_file_get_boolean_helper (keyfile, "main", "X-NM-Use-NAT-T", error);
		if (*error)
			goto error;
		force_natt = key_file_get_boolean_helper (keyfile, "main", "X-NM-Force-NAT-T", error);
		if (*error)
			goto error;

		/* force-natt takes precence over plain natt */
		if (force_natt) {
			nm_setting_vpn_add_data_item (s_vpn,
			                              NM_VPNC_KEY_NAT_TRAVERSAL_MODE,
			                              NM_VPNC_NATT_MODE_NATT_ALWAYS);
		} else if (natt) {
			nm_setting_vpn_add_data_item (s_vpn,
			                              NM_VPNC_KEY_NAT_TRAVERSAL_MODE,
			                              NM_VPNC_NATT_MODE_NATT);
		}
	} else if (key_file_has_key_helper (keyfile, "main", "EnableNat")) {
		/* explicit EnableNat=0 disables NAT */
		nm_setting_vpn_add_data_item (s_vpn,
		                              NM_VPNC_KEY_NAT_TRAVERSAL_MODE,
		                              NM_VPNC_NATT_MODE_NONE);
	}

	if (key_file_get_integer_helper (keyfile, "main", "PeerTimeout", &val)) {
		if ((val == 0) || ((val >= 10) && (val <= 86400))) {
			char *tmp = g_strdup_printf ("%d", (gint) val);
			nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DPD_IDLE_TIMEOUT, tmp);
			g_free (tmp);
		}
	}

	bool_value = key_file_get_boolean_helper (keyfile, "main", "EnableLocalLAN", error);
	if (*error)
		goto error;
	if (bool_value)
		g_object_set (s_ip4, NM_SETTING_IP_CONFIG_NEVER_DEFAULT, TRUE, NULL);

	buf = key_file_get_string_helper (keyfile, "main", "DHGroup", error);
	if (*error)
		goto error;
	if (buf) {
		if (!strcmp (buf, "1") || !strcmp (buf, "2") || !strcmp (buf, "5") || !strcmp (buf, "14") || !strcmp (buf, "15") || !strcmp (buf, "16") || !strcmp (buf, "17") || !strcmp (buf, "18")) {
			char *tmp;
			tmp = g_strdup_printf ("dh%s", buf);
			nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DHGROUP, tmp);
			g_free (tmp);
		}
		g_free (buf);
	}

	buf = key_file_get_string_helper (keyfile, "main", "X-NM-Routes", error);
	if (*error)
		goto error;
	if (buf) {
		add_routes (s_ip4, buf);
		g_free (buf);
	}

	if (key_file_get_integer_helper (keyfile, "main", "TunnelingMode", &val)) {
		/* If applicable, put up warning that TCP tunneling will be disabled */
		if (val == 1) {
			char *basename;

			basename = g_path_get_basename (path);
			g_warning (_("The VPN settings file “%s” specifies that VPN traffic should be tunneled through TCP which is currently not supported in the vpnc software.\n\nThe connection can still be created, with TCP tunneling disabled, however it may not work as expected."), basename);
			g_free (basename);
		}
	}

	/* UseLegacyIKEPort=0 uses dynamic source IKE port instead of 500.
	 * http://www.cisco.com/en/US/products/sw/secursw/ps2308/products_administration_guide_chapter09186a008015cfdc.html#1192555
	 * See also: http://support.microsoft.com/kb/928310
	 */
	found = key_file_get_integer_helper (keyfile, "main", "UseLegacyIKEPort", &val);
	if (!found || val != 0) {
		char *tmp;
		tmp = g_strdup_printf ("%d", (gint) NM_VPNC_LOCAL_PORT_DEFAULT); /* Use default vpnc local port: 500 */
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_LOCAL_PORT, tmp);
		g_free (tmp);
	}

	g_key_file_free (keyfile);
	return connection;

error:
	if (connection)
		g_object_unref (connection);
	g_key_file_free (keyfile);
	return NULL;
}

static gboolean
export (NMVpnEditorPlugin *plugin,
        const char *path,
        NMConnection *connection,
        GError **error)
{
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingVpn *s_vpn;
	FILE *f;
	const char *value;
	const char *gateway = NULL;
	GString *interface_name = NULL;
	gboolean enablenat = TRUE;
	gboolean singledes = FALSE;
	const char *groupname = NULL;
	const char *username = NULL;
	const char *domain = NULL;
	const char *peertimeout = NULL;
	const char *dhgroup = NULL;
	const char *group_pw = NULL;
	GString *routes = NULL;
	GString *uselegacyikeport = NULL;
	gboolean success = FALSE;
	guint32 routes_count = 0;
	gboolean save_password = FALSE;
	gboolean save_group_password = FALSE;
	gboolean use_natt = FALSE;
	gboolean use_force_natt = FALSE;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	s_con = nm_connection_get_setting_connection (connection);
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	s_vpn = nm_connection_get_setting_vpn (connection);

	f = fopen (path, "w");
	if (!f) {
		g_set_error_literal (error,
		                     NM_VPNC_IMPORT_EXPORT_ERROR,
		                     NM_VPNC_IMPORT_EXPORT_ERROR_UNKNOWN,
		                     "could not open file for writing");
		return FALSE;
	}

	interface_name = g_string_new("");
	value = nm_setting_connection_get_interface_name (s_con);
	if (value && strlen (value))
		g_string_printf (interface_name, "InterfaceName=%s\n", value);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_GATEWAY);
	if (value && strlen (value))
		gateway = value;
	else {
		g_set_error_literal (error,
		                     NM_VPNC_IMPORT_EXPORT_ERROR,
		                     NM_VPNC_IMPORT_EXPORT_ERROR_BAD_DATA,
		                     "connection was incomplete (missing gateway)");
		goto done;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_ID);
	if (value && strlen (value))
		groupname = value;
	else {
		g_set_error_literal (error,
		                     NM_VPNC_IMPORT_EXPORT_ERROR,
		                     NM_VPNC_IMPORT_EXPORT_ERROR_BAD_DATA,
		                     "connection was incomplete (missing group)");
		goto done;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER);
	if (value && strlen (value))
		username = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_DOMAIN);
	if (value && strlen (value))
		domain = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_SINGLE_DES);
	if (value && !strcmp (value, "yes"))
		singledes = TRUE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	if (value && strlen (value)) {
		if (!strcmp (value, NM_VPNC_NATT_MODE_CISCO)) {
			enablenat = TRUE;
			use_natt = FALSE;
		} else if (!strcmp (value, NM_VPNC_NATT_MODE_NATT)) {
			enablenat = TRUE;
			use_natt = TRUE;
		} else if (!strcmp (value, NM_VPNC_NATT_MODE_NATT_ALWAYS)) {
			enablenat = TRUE;
			use_natt = TRUE;
			use_force_natt = TRUE;
		}
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_DPD_IDLE_TIMEOUT);
	if (value && strlen (value))
		peertimeout = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_DHGROUP);
	if (value && strlen (value)) {
		dhgroup = (value[0] == 'd' && value[1] == 'h') ? value + 2 : NULL;
	}

	if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_VPNC_KEY_XAUTH_PASSWORD, &flags, NULL)) {
		if (!(flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
			save_password = TRUE;
	} else {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD_TYPE);
		if (value && strlen (value)) {
			if (!strcmp (value, NM_VPNC_PW_TYPE_SAVE))
				save_password = TRUE;
		}
	}

	/* Group password stuff */
	if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_VPNC_KEY_SECRET, &flags, NULL)) {
		if (!(flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
			save_group_password = TRUE;
	} else {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_SECRET_TYPE);
		if (value && strlen (value)) {
			if (!strcmp (value, NM_VPNC_PW_TYPE_SAVE))
				save_group_password = TRUE;
		}
	}
	if (save_group_password)
		group_pw = nm_setting_vpn_get_secret (s_vpn, NM_VPNC_KEY_SECRET);

	routes = g_string_new ("X-NM-Routes=");
	if (s_ip4 && nm_setting_ip_config_get_num_routes (s_ip4)) {
		int i;

		for (i = 0; i < nm_setting_ip_config_get_num_routes (s_ip4); i++) {
			NMIPRoute *route = nm_setting_ip_config_get_route (s_ip4, i);

			if (routes_count)
				g_string_append_c (routes, ' ');
			g_string_append_printf (routes, "%s/%d",
			                        nm_ip_route_get_dest (route),
			                        nm_ip_route_get_prefix (route));
			routes_count++;
		}
	}
	if (!routes_count) {
		g_string_free (routes, TRUE);
		routes = NULL;
	}

	uselegacyikeport = g_string_new ("");
	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_LOCAL_PORT);
	if (!value || !strcmp (value, "0"))
		g_string_assign (uselegacyikeport, "UseLegacyIKEPort=0\n");

	fprintf (f, 
		 "[main]\n"
		 "Description=%s\n"
		 "%s"
		 "Host=%s\n"
		 "AuthType=1\n"
		 "GroupName=%s\n"
		 "GroupPwd=%s\n"
		 "EnableISPConnect=0\n"
		 "ISPConnectType=0\n"
		 "ISPConnect=\n"
		 "ISPCommand=\n"
		 "Username=%s\n"
		 "SaveUserPassword=%s\n"
		 "EnableBackup=0\n"
		 "BackupServer=\n"
		 "EnableNat=%s\n"
		 "CertStore=0\n"
		 "CertName=\n"
		 "CertPath=\n"
		 "CertSubjectName=\n"
		 "CertSerialHash=\n"
		 "DHGroup=%s\n"
		 "ForceKeepAlives=0\n"
		 "enc_GroupPwd=\n"
		 "UserPassword=\n"
		 "enc_UserPassword=\n"
		 "NTDomain=%s\n"
		 "EnableMSLogon=0\n"
		 "MSLogonType=0\n"
		 "TunnelingMode=0\n"
		 "TcpTunnelingPort=10000\n"
		 "PeerTimeout=%s\n"
		 "EnableLocalLAN=1\n"
		 "SendCertChain=0\n"
		 "VerifyCertDN=\n"
		 "EnableSplitDNS=1\n"
		 "SingleDES=%s\n"
		 "SPPhonebook=\n"
		 "%s"
		 "X-NM-Use-NAT-T=%s\n"
		 "X-NM-Force-NAT-T=%s\n"
		 "X-NM-SaveGroupPassword=%s\n"
		 "%s\n",
		 /* Description */   nm_setting_connection_get_id (s_con),
		 /* InterfaceName */ (interface_name->len) ? interface_name->str : "",
		 /* Host */          gateway,
		 /* GroupName */     groupname,
		 /* GroupPassword */ group_pw ? group_pw : "",
		 /* Username */      username != NULL ? username : "",
		 /* Save Password */ save_password ? "1" : "0",
		 /* EnableNat */     enablenat ? "1" : "0",
		 /* DHGroup */       dhgroup != NULL ? dhgroup : "2",
		 /* NTDomain */      domain != NULL ? domain : "",
		 /* PeerTimeout */   peertimeout != NULL ? peertimeout : "0",
		 /* SingleDES */     singledes ? "1" : "0",
		 /* UseLegacyIKEPort */ (uselegacyikeport->len) ? uselegacyikeport->str : "",
		 /* X-NM-Use-NAT-T */ use_natt ? "1" : "0",
		 /* X-NM-Force-NAT-T */ use_force_natt ? "1" : "0",
		 /* X-NM-SaveGroupPassword */ save_group_password ? "1" : "0",
		 /* X-NM-Routes */   (routes && routes->str) ? routes->str : "");

	success = TRUE;

done:
	if (interface_name)
		g_string_free (interface_name, TRUE);
	if (routes)
		g_string_free (routes, TRUE);
	if (uselegacyikeport)
		g_string_free (uselegacyikeport, TRUE);
	fclose (f);
	return success;
}

static char *
get_suggested_filename (NMVpnEditorPlugin *plugin, NMConnection *connection)
{
	NMSettingConnection *s_con;
	const char *id;

	g_return_val_if_fail (connection != NULL, NULL);

	s_con = nm_connection_get_setting_connection (connection);
	g_return_val_if_fail (s_con != NULL, NULL);

	id = nm_setting_connection_get_id (s_con);
	g_return_val_if_fail (id != NULL, NULL);

	return g_strdup_printf ("%s.pcf", id);
}

static guint32
get_capabilities (NMVpnEditorPlugin *plugin)
{
	return (NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT | NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT);
}

static NMVpnEditor *
_call_editor_factory (gpointer factory,
                      NMVpnEditorPlugin *editor_plugin,
                      NMConnection *connection,
                      gpointer user_data,
                      GError **error)
{
	return ((NMVpnEditorFactory) factory) (editor_plugin,
	                                       connection,
	                                       error);
}

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	gpointer gtk3_only_symbol;
	GModule *self_module;
	const char *editor;

	g_return_val_if_fail (VPNC_IS_EDITOR_PLUGIN (iface), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	self_module = g_module_open (NULL, 0);
	g_module_symbol (self_module, "gtk_container_add", &gtk3_only_symbol);
	g_module_close (self_module);

	if (gtk3_only_symbol) {
		editor = "libnm-vpn-plugin-vpnc-editor.so";
	} else {
		editor = "libnm-gtk4-vpn-plugin-vpnc-editor.so";
	}

	return nm_vpn_plugin_utils_load_editor (editor,
						"nm_vpn_editor_factory_vpnc",
						_call_editor_factory,
						iface,
						connection,
						NULL,
						error);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, VPNC_PLUGIN_NAME);
		break;
	case PROP_DESC:
		g_value_set_string (value, VPNC_PLUGIN_DESC);
		break;
	case PROP_SERVICE:
		g_value_set_string (value, NM_DBUS_SERVICE_VPNC);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
vpnc_editor_plugin_init (VpncEditorPlugin *plugin)
{
}

static void
vpnc_editor_plugin_class_init (VpncEditorPluginClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
	                                  PROP_NAME,
	                                  NM_VPN_EDITOR_PLUGIN_NAME);

	g_object_class_override_property (object_class,
	                                  PROP_DESC,
	                                  NM_VPN_EDITOR_PLUGIN_DESCRIPTION);

	g_object_class_override_property (object_class,
	                                  PROP_SERVICE,
	                                  NM_VPN_EDITOR_PLUGIN_SERVICE);
}

static void
vpnc_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface)
{
	/* interface implementation */
	iface->get_editor = get_editor;
	iface->get_capabilities = get_capabilities;
	iface->import_from_file = import;
	iface->export_to_file = export;
	iface->get_suggested_filename = get_suggested_filename;
}

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

	return g_object_new (VPNC_TYPE_EDITOR_PLUGIN, NULL);
}


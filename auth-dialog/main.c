/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
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
 * (C) Copyright 2004 - 2011 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <gnome-keyring-memory.h>

#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>

#include "common-gnome/keyring-helpers.h"
#include "src/nm-vpnc-service.h"
#include "gnome-two-password-dialog.h"

static gboolean
get_secrets (const char *vpn_uuid,
             const char *vpn_name,
             gboolean retry,
             const char *in_upw,
             char **out_upw,
             const char *upw_type,
             const char *in_gpw,
             char **out_gpw,
             const char *gpw_type)
{
	VpnPasswordDialog *dialog;
	gboolean is_session = TRUE;
	gboolean found_upw = FALSE;
	gboolean found_gpw = FALSE;
	char *prompt;
	gboolean success = FALSE;

	g_return_val_if_fail (vpn_uuid != NULL, FALSE);
	g_return_val_if_fail (vpn_name != NULL, FALSE);
	g_return_val_if_fail (out_upw != NULL, FALSE);
	g_return_val_if_fail (*out_upw == NULL, FALSE);
	g_return_val_if_fail (out_gpw != NULL, FALSE);
	g_return_val_if_fail (*out_gpw == NULL, FALSE);

	/* If a password type wasn't present in the VPN connection details, then
	 * default to saving the password if it was found in the keyring.  But if
	 * it wasn't found in the keyring, default to always asking for the password.
	 */

	if (in_upw) {
		*out_upw = gnome_keyring_memory_strdup (in_upw);
		found_upw = TRUE;
	} else {
		found_upw = keyring_helpers_get_one_secret (vpn_uuid, VPNC_USER_PASSWORD, out_upw, &is_session);
		if (!upw_type)
			upw_type = found_upw ? NM_VPNC_PW_TYPE_SAVE : NM_VPNC_PW_TYPE_ASK;
		else if (!strcmp (upw_type, NM_VPNC_PW_TYPE_UNUSED)) {
			gnome_keyring_memory_free (*out_upw);
			*out_upw = NULL;
		}
	}

	if (in_gpw) {
		*out_gpw = gnome_keyring_memory_strdup (in_gpw);
		found_gpw = TRUE;
	} else {
		found_gpw = keyring_helpers_get_one_secret (vpn_uuid, VPNC_GROUP_PASSWORD, out_gpw, &is_session);
		if (!gpw_type)
			gpw_type = found_gpw ? NM_VPNC_PW_TYPE_SAVE : NM_VPNC_PW_TYPE_ASK;
		else if (!strcmp (gpw_type, NM_VPNC_PW_TYPE_UNUSED)) {
			gnome_keyring_memory_free (*out_gpw);
			*out_gpw = NULL;
		}
	}

	if (!retry) {
		gboolean need_upw = TRUE, need_gpw = TRUE;

		/* Don't ask if both passwords are either saved and present, or unused */
		if (   (!strcmp (upw_type, NM_VPNC_PW_TYPE_SAVE) && found_upw && *out_upw)
		    || (!upw_type && found_upw && *out_upw)  /* treat unknown type as "save" */
		    || !strcmp (upw_type, NM_VPNC_PW_TYPE_UNUSED))
			need_upw = FALSE;

		if (   (!strcmp (gpw_type, NM_VPNC_PW_TYPE_SAVE) && found_gpw && *out_gpw)
		    || (!gpw_type && found_gpw && *out_gpw)  /* treat unknown type as "save" */
		    || !strcmp (gpw_type, NM_VPNC_PW_TYPE_UNUSED))
			need_gpw = FALSE;

		if (!need_upw && !need_gpw)
			return TRUE;
	} else {
		/* Don't ask if both passwords are unused */
		if (   !strcmp (upw_type, NM_VPNC_PW_TYPE_UNUSED)
		    && !strcmp (gpw_type, NM_VPNC_PW_TYPE_UNUSED))
			return TRUE;
	}

	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), vpn_name);
	dialog = VPN_PASSWORD_DIALOG (vpn_password_dialog_new (_("Authenticate VPN"), prompt, NULL));
	g_free (prompt);

	vpn_password_dialog_set_show_remember (dialog, FALSE);
	vpn_password_dialog_set_password_secondary_label (dialog, _("_Group Password:"));

	if (!strcmp (upw_type, NM_VPNC_PW_TYPE_UNUSED))
		vpn_password_dialog_set_show_password (dialog, FALSE);
	else if (!retry && found_upw && strcmp (upw_type, NM_VPNC_PW_TYPE_ASK))
		vpn_password_dialog_set_show_password (dialog, FALSE);

	if (!strcmp (gpw_type, NM_VPNC_PW_TYPE_UNUSED))
		vpn_password_dialog_set_show_password_secondary (dialog, FALSE);
	else if (!retry && found_gpw && strcmp (gpw_type, NM_VPNC_PW_TYPE_ASK))
		vpn_password_dialog_set_show_password_secondary (dialog, FALSE);

	/* On reprompt the first entry of type 'ask' gets the focus */
	if (retry) {
		if (!strcmp (upw_type, NM_VPNC_PW_TYPE_ASK))
			vpn_password_dialog_focus_password (dialog);
		else if (!strcmp (gpw_type, NM_VPNC_PW_TYPE_ASK))
			vpn_password_dialog_focus_password_secondary (dialog);
	}

	/* if retrying, pre-fill dialog with the password */
	if (*out_upw) {
		vpn_password_dialog_set_password (dialog, *out_upw);
		gnome_keyring_memory_free (*out_upw);
		*out_upw = NULL;
	}
	if (*out_gpw) {
		vpn_password_dialog_set_password_secondary (dialog, *out_gpw);
		gnome_keyring_memory_free (*out_gpw);
		*out_gpw = NULL;
	}

	gtk_widget_show (GTK_WIDGET (dialog));

	success = vpn_password_dialog_run_and_block (dialog);
	if (success) {
		*out_upw = gnome_keyring_memory_strdup (vpn_password_dialog_get_password (dialog));
		*out_gpw = gnome_keyring_memory_strdup (vpn_password_dialog_get_password_secondary (dialog));

		if (!strcmp (upw_type, NM_VPNC_PW_TYPE_SAVE)) {
			if (*out_upw)
				keyring_helpers_save_secret (vpn_uuid, vpn_name, NULL, VPNC_USER_PASSWORD, *out_upw);
		} else if (   !strcmp (upw_type, NM_VPNC_PW_TYPE_ASK)
		         || !strcmp (upw_type, NM_VPNC_PW_TYPE_UNUSED)) {
			/* Clear the password from the keyring */
			keyring_helpers_delete_secret (vpn_uuid, VPNC_USER_PASSWORD);
		}

		if (!strcmp (gpw_type, NM_VPNC_PW_TYPE_SAVE)) {
			if (*out_gpw)
				keyring_helpers_save_secret (vpn_uuid, vpn_name, NULL, VPNC_GROUP_PASSWORD, *out_gpw);
		} else if (   !strcmp (gpw_type, NM_VPNC_PW_TYPE_ASK)
		         || !strcmp (gpw_type, NM_VPNC_PW_TYPE_UNUSED)) {
			/* Clear the password from the keyring */
			keyring_helpers_delete_secret (vpn_uuid, VPNC_GROUP_PASSWORD);
		}
	}

	gtk_widget_hide (GTK_WIDGET (dialog));
	gtk_widget_destroy (GTK_WIDGET (dialog));

	return success;
}

#define DATA_KEY_TAG "DATA_KEY="
#define DATA_VAL_TAG "DATA_VAL="
#define SECRET_KEY_TAG "SECRET_KEY="
#define SECRET_VAL_TAG "SECRET_VAL="

static gboolean
get_vpn_data_and_secrets (GHashTable **data, GHashTable **secrets)
{
	gboolean success = FALSE;
	gchar c;
	GString *line;
	char *key = NULL, *val = NULL;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (*data == NULL, FALSE);
	g_return_val_if_fail (secrets != NULL, FALSE);
	g_return_val_if_fail (*secrets == NULL, FALSE);

	*data = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	*secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, gnome_keyring_memory_free);

	line = g_string_new ("");

	/* Read stdin for data and secret items until we get a DONE */
	while (1) {
		ssize_t nr;
		GHashTable *hash = NULL;

		errno = 0;
		nr = read (0, &c, 1);
		if (nr == -1) {
			if (errno == EAGAIN) {
				g_usleep (100);
				continue;
			}
			break;
		}

		if (c != '\n') {
			g_string_append_c (line, c);
			continue;
		}

		/* Check for the finish marker */
		if (strcmp (line->str, "DONE") == 0)
			break;

		/* Otherwise it's a data/secret item */
		if (strncmp (line->str, DATA_KEY_TAG, strlen (DATA_KEY_TAG)) == 0) {
			hash = *data;
			key = g_strdup (line->str + strlen (DATA_KEY_TAG));
		} else if (strncmp (line->str, DATA_VAL_TAG, strlen (DATA_VAL_TAG)) == 0) {
			hash = *data;
			val = g_strdup (line->str + strlen (DATA_VAL_TAG));
		} else if (strncmp (line->str, SECRET_KEY_TAG, strlen (SECRET_KEY_TAG)) == 0) {
			hash = *secrets;
			key = g_strdup (line->str + strlen (SECRET_KEY_TAG));
		} else if (strncmp (line->str, SECRET_VAL_TAG, strlen (SECRET_VAL_TAG)) == 0) {
			hash = *secrets;
			val = gnome_keyring_memory_strdup (line->str + strlen (SECRET_VAL_TAG));
		}
		g_string_truncate (line, 0);

		if (key && val && hash) {
			g_hash_table_insert (hash, key, val);
			key = NULL;
			val = NULL;
			success = TRUE;  /* Got at least one value */
		}
	}

	g_string_free (line, TRUE);
	return success;
}

static void
wait_for_quit (void)
{
	GString *str;
	char c;
	ssize_t n;
	time_t start;

	str = g_string_sized_new (10);
	start = time (NULL);
	do {
		errno = 0;
		n = read (0, &c, 1);
		if (n == 0 || (n < 0 && errno == EAGAIN))
			g_usleep (G_USEC_PER_SEC / 10);
		else if (n == 1) {
			g_string_append_c (str, c);
			if (strstr (str->str, "QUIT") || (str->len > 10))
				break;
		} else
			break;
	} while (time (NULL) < start + 20);
	g_string_free (str, TRUE);
}

int 
main (int argc, char *argv[])
{
	gboolean retry = FALSE;
	char *vpn_name = NULL, *vpn_uuid = NULL, *vpn_service = NULL;
	GHashTable *data = NULL, *secrets = NULL;
	char *password = NULL, *group_password = NULL;
	GError *error = NULL;
	GOptionContext *context;
	GOptionEntry entries[] = {
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ NULL }
		};

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	gtk_init (&argc, &argv);
	textdomain (GETTEXT_PACKAGE);

	context = g_option_context_new ("- vpnc auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		fprintf (stderr, "Error parsing options: %s\n", error->message);
		g_error_free (error);
		return 1;
	}

	g_option_context_free (context);

	if (!vpn_uuid || !vpn_service || !vpn_name) {
		fprintf (stderr, "A connection UUID, name, and VPN plugin service name are required.\n");
		return 1;
	}

	if (strcmp (vpn_service, NM_DBUS_SERVICE_VPNC) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_VPNC);
		return 1;
	}

	if (!get_vpn_data_and_secrets (&data, &secrets)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.",
		         vpn_name, vpn_uuid);
		return 1;
	}

	if (!get_secrets (vpn_uuid, vpn_name, retry,
	                  g_hash_table_lookup (secrets, NM_VPNC_KEY_XAUTH_PASSWORD),
	                  &password,
	                  g_hash_table_lookup (data, NM_VPNC_KEY_XAUTH_PASSWORD_TYPE),
	                  g_hash_table_lookup (secrets, NM_VPNC_KEY_SECRET),
	                  &group_password,
	                  g_hash_table_lookup (data, NM_VPNC_KEY_SECRET_TYPE)))
		return 1;

	/* dump the passwords to stdout */
	if (password)
		printf ("%s\n%s\n", NM_VPNC_KEY_XAUTH_PASSWORD, password);
	if (group_password)
		printf ("%s\n%s\n", NM_VPNC_KEY_SECRET, group_password);
	printf ("\n\n");

	if (password) {
		memset (password, 0, strlen (password));
		gnome_keyring_memory_free (password);
	}
	if (group_password) {
		memset (group_password, 0, strlen (group_password));
		gnome_keyring_memory_free (group_password);
	}

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	/* Wait for quit signal */
	wait_for_quit ();

	if (data)
		g_hash_table_unref (data);
	if (secrets)
		g_hash_table_unref (secrets);
	return 0;
}

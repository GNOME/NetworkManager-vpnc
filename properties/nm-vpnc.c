/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * CVSID: $Id: nm-vpnc.c 4366 2008-12-06 00:19:59Z dcbw $
 *
 * nm-vpnc.c : GNOME UI dialogs for configuring vpnc VPN connections
 *
 * Copyright (C) 2005 David Zeuthen, <davidz@redhat.com>
 * Copyright (C) 2005 - 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2005 - 2011 Red Hat, Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <glib/gi18n-lib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <gnome-keyring.h>
#include <gnome-keyring-memory.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "src/nm-vpnc-service.h"
#include "common-gnome/keyring-helpers.h"
#include "pcf-file.h"
#include "nm-vpnc.h"

#define VPNC_PLUGIN_NAME    _("Cisco Compatible VPN (vpnc)")
#define VPNC_PLUGIN_DESC    _("Compatible with various Cisco, Juniper, Netscreen, and Sonicwall IPSec-based VPN gateways.")
#define VPNC_PLUGIN_SERVICE NM_DBUS_SERVICE_VPNC 

#define ENC_TYPE_SECURE 0
#define ENC_TYPE_WEAK   1
#define ENC_TYPE_NONE   2

#define PW_TYPE_SAVE   0
#define PW_TYPE_ASK	   1
#define PW_TYPE_UNUSED 2

#define NM_VPNC_LOCAL_PORT_DEFAULT 500

/************** plugin class **************/

static void vpnc_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (VpncPluginUi, vpnc_plugin_ui, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_INTERFACE,
											   vpnc_plugin_ui_interface_init))

/************** UI widget class **************/

static void vpnc_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (VpncPluginUiWidget, vpnc_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE,
											   vpnc_plugin_ui_widget_interface_init))

#define VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), VPNC_TYPE_PLUGIN_UI_WIDGET, VpncPluginUiWidgetPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkSizeGroup *group;
	gint orig_dpd_timeout;
	gboolean new_connection;
} VpncPluginUiWidgetPrivate;


#define VPNC_PLUGIN_UI_ERROR vpnc_plugin_ui_error_quark ()

static GQuark
vpnc_plugin_ui_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("vpnc-plugin-ui-error-quark");

	return error_quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
vpnc_plugin_ui_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (VPNC_PLUGIN_UI_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (VPNC_PLUGIN_UI_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (VPNC_PLUGIN_UI_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The connection was missing invalid. */
			ENUM_ENTRY (VPNC_PLUGIN_UI_ERROR_INVALID_CONNECTION, "InvalidConnection"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("VpncPluginUiError", values);
	}
	return etype;
}


static gboolean
check_validity (VpncPluginUiWidget *self, GError **error)
{
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	char *str;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str) || strstr (str, " ") || strstr (str, "\t")) {
		g_set_error (error,
		             VPNC_PLUGIN_UI_ERROR,
		             VPNC_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_VPNC_KEY_GATEWAY);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             VPNC_PLUGIN_UI_ERROR,
		             VPNC_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_VPNC_KEY_ID);
		return FALSE;
	}

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (VPNC_PLUGIN_UI_WIDGET (user_data), "changed");
}

static gboolean
fill_vpn_passwords (VpncPluginUiWidget *self, NMConnection *connection)
{
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	gboolean success = FALSE;
	char *password = NULL;
	char *group_password = NULL;

	/* Grab secrets from the connection or the keyring */
	if (connection) {
		NMSettingConnection *s_con;
		NMSettingVPN *s_vpn;
		NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;
		const char *tmp;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));

		s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
		if (s_vpn) {
			tmp = nm_setting_vpn_get_secret (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD);
			if (tmp)
				password = gnome_keyring_memory_strdup (tmp);

			tmp = nm_setting_vpn_get_secret (s_vpn, NM_VPNC_KEY_SECRET);
			if (tmp)
				group_password = gnome_keyring_memory_strdup (tmp);
		}

		nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_VPNC_KEY_XAUTH_PASSWORD, &secret_flags, NULL);
		if (!password && (secret_flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED)) {
			keyring_helpers_get_one_secret (nm_setting_connection_get_uuid (s_con),
				                            VPNC_USER_PASSWORD,
				                            &password);
		}

		secret_flags = NM_SETTING_SECRET_FLAG_NONE;
		nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_VPNC_KEY_SECRET, &secret_flags, NULL);
		if (!group_password && (secret_flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED)) {
			keyring_helpers_get_one_secret (nm_setting_connection_get_uuid (s_con),
			                                VPNC_GROUP_PASSWORD,
			                                &group_password);
		}
	}

	/* User password */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_password_entry"));
	if (!widget)
		goto out;
	if (password)
		gtk_entry_set_text (GTK_ENTRY (widget), password);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Group password */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_password_entry"));
	if (!widget)
		goto out;
	if (group_password)
		gtk_entry_set_text (GTK_ENTRY (widget), group_password);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	success = TRUE;

out:
	gnome_keyring_memory_free (password);
	gnome_keyring_memory_free (group_password);

	return success;
}

static void
show_toggled_cb (GtkCheckButton *button, VpncPluginUiWidget *self)
{
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	gboolean visible;

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_password_entry"));
	g_assert (widget);
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_password_entry"));
	g_assert (widget);
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

static void
pw_type_changed_helper (VpncPluginUiWidget *self, GtkWidget *combo)
{
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	const char *entry = NULL;
	GtkWidget *widget;

	/* If the user chose "Not required", desensitize and clear the correct
	 * password entry.
	 */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_pass_type_combo"));
	if (combo == widget)
		entry = "user_password_entry";
	else {
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_pass_type_combo"));
		if (combo == widget)
			entry = "group_password_entry";
	}
	if (!entry)
		return;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, entry));
	g_assert (widget);

	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (combo))) {
	case PW_TYPE_ASK:
	case PW_TYPE_UNUSED:
		gtk_entry_set_text (GTK_ENTRY (widget), "");
		gtk_widget_set_sensitive (widget, FALSE);
		break;
	default:
		gtk_widget_set_sensitive (widget, TRUE);
		break;
	}
}

static void
pw_type_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	VpncPluginUiWidget *self = VPNC_PLUGIN_UI_WIDGET (user_data);

	pw_type_changed_helper (self, combo);
	stuff_changed_cb (combo, self);
}

static const char *
secret_flags_to_pw_type (NMSettingVPN *s_vpn, const char *key)
{
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), key, &flags, NULL)) {
		if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
			return NM_VPNC_PW_TYPE_UNUSED;
		if (flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
			return NM_VPNC_PW_TYPE_ASK;
		return NM_VPNC_PW_TYPE_SAVE;
	}
	return NULL;
}

static void
init_one_pw_combo (VpncPluginUiWidget *self,
                   NMSettingVPN *s_vpn,
                   const char *combo_name,
                   const char *secret_key,
                   const char *type_key,
                   const char *entry_name)
{
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	int active = -1;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	const char *value = NULL;
	guint32 default_idx = 1;

	/* If there's already a password and the password type can't be found in
	 * the VPN settings, default to saving it.  Otherwise, always ask for it.
	 */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, entry_name));
	if (widget) {
		const char *tmp;

		tmp = gtk_entry_get_text (GTK_ENTRY (widget));
		if (tmp && strlen (tmp))
			default_idx = 0;
	}

	store = gtk_list_store_new (1, G_TYPE_STRING);
	if (s_vpn) {
		value = secret_flags_to_pw_type (s_vpn, secret_key);
		if (!value)
			value = nm_setting_vpn_get_data_item (s_vpn, type_key);
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Saved"), -1);
	if ((active < 0) && value) {
		if (!strcmp (value, NM_VPNC_PW_TYPE_SAVE))
			active = 0;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Always Ask"), -1);
	if ((active < 0) && value) {
		if (!strcmp (value, NM_VPNC_PW_TYPE_ASK))
			active = 1;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Not Required"), -1);
	if ((active < 0) && value) {
		if (!strcmp (value, NM_VPNC_PW_TYPE_UNUSED))
			active = 2;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, combo_name));
	g_assert (widget);
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? default_idx : active);
	pw_type_changed_helper (self, widget);

	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (pw_type_combo_changed_cb), self);
}

static gboolean
init_plugin_ui (VpncPluginUiWidget *self, NMConnection *connection, GError **error)
{
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	const char *value = NULL;
	int active = -1;
	const char *natt_mode = NULL;
	const char *ike_dh_group = NULL;

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_GATEWAY);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_ID);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "encryption_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));

	store = gtk_list_store_new (1, G_TYPE_STRING);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Secure (default)"), -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Weak (use with caution)"), -1);
	if (s_vpn && (active < 0)) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_SINGLE_DES);
		if (value && !strcmp (value, "yes"))
			active = 1;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("None (completely insecure)"), -1);
	if (s_vpn && (active < 0)) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NO_ENCRYPTION);
		if (value && !strcmp (value, "yes"))
			active = 2;
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Fill the VPN passwords *before* initializing the PW type combos, since
	 * knowing if there are passwords when initializing the combos is helpful.
	 */
	fill_vpn_passwords (self, connection);

	init_one_pw_combo (self,
	                   s_vpn,
	                   "user_pass_type_combo",
	                   NM_VPNC_KEY_XAUTH_PASSWORD,
	                   NM_VPNC_KEY_XAUTH_PASSWORD_TYPE,
	                   "user_password_entry");
	init_one_pw_combo (self,
	                   s_vpn,
	                   "group_pass_type_combo",
	                   NM_VPNC_KEY_SECRET,
	                   NM_VPNC_KEY_SECRET_TYPE,
	                   "group_password_entry");

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "domain_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_DOMAIN);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	active = -1;
	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	if (s_vpn)
		natt_mode = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("NAT-T when available (default)"), 1, NM_VPNC_NATT_MODE_NATT, -1);
	if ((active < 0) && natt_mode) {
		if (!strcmp (natt_mode, NM_VPNC_NATT_MODE_NATT))
			active = 0;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("NAT-T always"), 1, NM_VPNC_NATT_MODE_NATT_ALWAYS, -1);
	if ((active < 0) && natt_mode) {
		if (!strcmp (natt_mode, NM_VPNC_NATT_MODE_NATT_ALWAYS))
			active = 1;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Cisco UDP"), 1, NM_VPNC_NATT_MODE_CISCO, -1);
	if ((active < 0) && natt_mode) {
		if (!strcmp (natt_mode, NM_VPNC_NATT_MODE_CISCO))
			active = 2;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Disabled"), 1, NM_VPNC_NATT_MODE_NONE, -1);
	if ((active < 0) && natt_mode) {
		if (!strcmp (natt_mode, NM_VPNC_NATT_MODE_NONE))
			active = 3;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "natt_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	active = -1;
	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	if (s_vpn)
		ike_dh_group = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_DHGROUP);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 1"), 1, NM_VPNC_DHGROUP_DH1, -1);
	if ((active < 0) && ike_dh_group) {
		if (!strcmp (ike_dh_group, NM_VPNC_DHGROUP_DH1))
			active = 0;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 2 (default)"), 1, NM_VPNC_DHGROUP_DH2, -1);
	if ((active < 0) && ike_dh_group) {
		if (!strcmp (ike_dh_group, NM_VPNC_DHGROUP_DH2))
			active = 1;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 5"), 1, NM_VPNC_DHGROUP_DH5, -1);
	if ((active < 0) && ike_dh_group) {
		if (!strcmp (ike_dh_group, NM_VPNC_DHGROUP_DH5))
			active = 2;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "dhgroup_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 1 : active);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "disable_dpd_checkbutton"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_DPD_IDLE_TIMEOUT);
		if (value) {
			long int tmp;

			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (tmp >= 0 && tmp <= G_MAXUINT32 && errno == 0)
				priv->orig_dpd_timeout = (guint32) tmp;

			if (priv->orig_dpd_timeout == 0)
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
		}
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "show_passwords_checkbutton"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "toggled",
	                  (GCallback) show_toggled_cb,
	                  self);

	return TRUE;
}

static GObject *
get_widget (NMVpnPluginUiWidgetInterface *iface)
{
	VpncPluginUiWidget *self = VPNC_PLUGIN_UI_WIDGET (iface);
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static guint32
handle_one_pw_type (NMSettingVPN *s_vpn,
                    GtkBuilder *builder,
                    const char *combo_name,
                    const char *secret_key,
                    const char *type_key,
                    gboolean new_connection)
{
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;
	GtkWidget *widget;
	guint32 pw_type;
	const char *data_val = NULL;

	nm_setting_get_secret_flags (NM_SETTING (s_vpn), secret_key, &flags, NULL);
	flags &= ~(NM_SETTING_SECRET_FLAG_NOT_SAVED | NM_SETTING_SECRET_FLAG_NOT_REQUIRED);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, combo_name));
	pw_type = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
	switch (pw_type) {
	case PW_TYPE_SAVE:
		data_val = NM_VPNC_PW_TYPE_SAVE;
		break;
	case PW_TYPE_UNUSED:
		data_val = NM_VPNC_PW_TYPE_UNUSED;
		flags |= NM_SETTING_SECRET_FLAG_NOT_REQUIRED;
		break;
	case PW_TYPE_ASK:
	default:
		pw_type = PW_TYPE_ASK;
		data_val = NM_VPNC_PW_TYPE_ASK;
		flags |= NM_SETTING_SECRET_FLAG_NOT_SAVED;
		break;
	}

	if (new_connection) {
		/* new connections default to agent-owned secrets */
		flags |= NM_SETTING_SECRET_FLAG_AGENT_OWNED;
	}

	nm_setting_vpn_add_data_item (s_vpn, type_key, data_val);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), secret_key, flags, NULL);
	return pw_type;
}

static gboolean
update_connection (NMVpnPluginUiWidgetInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	VpncPluginUiWidget *self = VPNC_PLUGIN_UI_WIDGET (iface);
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn, *s_vpn_orig;
	GtkWidget *widget;
	char *str;
	GtkTreeModel *model;
	GtkTreeIter iter;
	guint32 upw_type, gpw_type;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_VPNC, NULL);

	/* Gateway */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_GATEWAY, str);

	/* Group name */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_ID, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "domain_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DOMAIN, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "encryption_combo"));
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget))) {
	case ENC_TYPE_WEAK:
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_SINGLE_DES, "yes");
		break;
	case ENC_TYPE_NONE:
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_NO_ENCRYPTION, "yes");
		break;
	case ENC_TYPE_SECURE:
	default:
		break;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "natt_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		const char *mode = NULL;

		gtk_tree_model_get (model, &iter, 1, &mode, -1);
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE, mode);
	} else
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE, NM_VPNC_NATT_MODE_NATT);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "dhgroup_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		const char *dhgroup = NULL;

		gtk_tree_model_get (model, &iter, 1, &dhgroup, -1);
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DHGROUP, dhgroup);
	} else
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DHGROUP, NM_VPNC_DHGROUP_DH2);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "disable_dpd_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DPD_IDLE_TIMEOUT, "0");
	} else {
		/* If DPD was disabled and now the user wishes to enable it, just
		 * don't pass the DPD_IDLE_TIMEOUT option to vpnc and thus use the
		 * default DPD idle time.  Otherwise keep the original DPD idle timeout.
		 */
		if (priv->orig_dpd_timeout >= 10) {
			char *tmp = g_strdup_printf ("%d", priv->orig_dpd_timeout);
			nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DPD_IDLE_TIMEOUT, tmp);
			g_free (tmp);
		}
	}

	upw_type = handle_one_pw_type (s_vpn,
	                               priv->builder,
	                               "user_pass_type_combo",
	                               NM_VPNC_KEY_XAUTH_PASSWORD,
	                               NM_VPNC_KEY_XAUTH_PASSWORD_TYPE,
	                               priv->new_connection);
	gpw_type = handle_one_pw_type (s_vpn,
	                               priv->builder,
	                               "group_pass_type_combo",
	                               NM_VPNC_KEY_SECRET,
	                               NM_VPNC_KEY_SECRET_TYPE,
	                               priv->new_connection);

	/* User password */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_password_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str) && (upw_type != PW_TYPE_UNUSED))
		nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD, str);

	/* Group password */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_password_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str) && (gpw_type != PW_TYPE_UNUSED))
		nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_SECRET, str);

	/* Local Port is not in GUI (yet?). So when present in the connection,
	 * copy it from the old VPN setting to the new one to preserve it.
	 */
	s_vpn_orig = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	if (s_vpn_orig) {
		const char *local_port = nm_setting_vpn_get_data_item (s_vpn_orig, NM_VPNC_KEY_LOCAL_PORT);
		if (local_port && strlen (local_port))
			nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_LOCAL_PORT, local_port);
	}

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	return TRUE;
}

static void
is_new_func (const char *key, const char *value, gpointer user_data)
{
	gboolean *is_new = user_data;

	/* If there are any VPN data items the connection isn't new */
	*is_new = FALSE;
}

static NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnPluginUiWidgetInterface *object;
	VpncPluginUiWidgetPrivate *priv;
	char *ui_file;
	NMSettingVPN *s_vpn;
	gboolean new = TRUE;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE (g_object_new (VPNC_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, VPNC_PLUGIN_UI_ERROR, 0, "could not create vpnc object");
		return NULL;
	}

	priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	ui_file = g_strdup_printf ("%s/%s", UIDIR, "nm-vpnc-dialog.ui");
	priv->builder = gtk_builder_new ();

	if (!gtk_builder_add_from_file (priv->builder, ui_file, error)) {
		g_warning ("Couldn't load builder file: %s",
		           error && *error ? (*error)->message : "(unknown)");
		g_clear_error (error);
		g_set_error (error, VPNC_PLUGIN_UI_ERROR, 0,
		             "could not load required resources at %s", ui_file);
		g_free (ui_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (ui_file);

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "vpnc-vbox"));
	if (!priv->widget) {
		g_set_error (error, VPNC_PLUGIN_UI_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		nm_setting_vpn_foreach_data_item (s_vpn, is_new_func, &new);
	priv->new_connection = new;

	if (!init_plugin_ui (VPNC_PLUGIN_UI_WIDGET (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	VpncPluginUiWidget *plugin = VPNC_PLUGIN_UI_WIDGET (object);
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->builder)
		g_object_unref (priv->builder);

	G_OBJECT_CLASS (vpnc_plugin_ui_widget_parent_class)->dispose (object);
}

static void
vpnc_plugin_ui_widget_class_init (VpncPluginUiWidgetClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (VpncPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void
vpnc_plugin_ui_widget_init (VpncPluginUiWidget *plugin)
{
}

static void
vpnc_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static void
add_routes (NMSettingIP4Config *s_ip4, const char *routelist)
{
	char **substrs;
	unsigned int i;

	substrs = g_strsplit (routelist, " ", 0);
	for (i = 0; substrs[i] != NULL; i++) {
		struct in_addr tmp;
		char *p, *str_route;
		long int prefix = 32;

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

		/* don't pass the prefix to inet_pton() */
		*p = '\0';
		if (inet_pton (AF_INET, str_route, &tmp) > 0) {
			NMIP4Route *route = nm_ip4_route_new ();

			nm_ip4_route_set_dest (route, tmp.s_addr);
			nm_ip4_route_set_prefix (route, (guint32) prefix);

			nm_setting_ip4_config_add_route (s_ip4, route);
		} else
			g_warning ("Ignoring invalid route '%s'", str_route);

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

static NMConnection *
import (NMVpnPluginUiInterface *iface, const char *path, GError **error)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	GHashTable *pcf;
	const char *buf;
	gboolean bool_value;
	NMSettingIP4Config *s_ip4;
	gint val;
	gboolean found;

	pcf = pcf_file_load (path);
	if (!pcf) {
		g_set_error (error, 0, 0, "does not look like a %s VPN connection (parse failed)",
		             VPNC_PLUGIN_NAME);
		return NULL;
	}

	connection = nm_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_VPNC, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	/* Gateway */
	if (pcf_file_lookup_string (pcf, "main", "Host", &buf))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_GATEWAY, buf);
	else {
		g_set_error (error, 0, 0, "does not look like a %s VPN connection (no Host)",
		             VPNC_PLUGIN_NAME);
		g_object_unref (connection);
		return NULL;
	}

	/* Group name */
	if (pcf_file_lookup_string (pcf, "main", "GroupName", &buf))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_ID, buf);
	else {
		g_set_error (error, 0, 0, "does not look like a %s VPN connection (no GroupName)",
		             VPNC_PLUGIN_NAME);
		g_object_unref (connection);
		return NULL;
	}

	/* Optional settings */

	/* Connection name */
	if (pcf_file_lookup_string (pcf, "main", "Description", &buf))
		g_object_set (s_con, NM_SETTING_CONNECTION_ID, buf, NULL);

	if (pcf_file_lookup_string (pcf, "main", "UserName", &buf))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER, buf);

	if (pcf_file_lookup_string (pcf, "main", "UserPassword", &buf)) {
		nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD, buf);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn),
		                             NM_VPNC_KEY_XAUTH_PASSWORD,
		                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
		                             NULL);
	}

	if (pcf_file_lookup_bool (pcf, "main", "SaveUserPassword", &bool_value)) {
		NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_AGENT_OWNED;

		if (bool_value) {
			nm_setting_vpn_add_data_item (s_vpn,
			                              NM_VPNC_KEY_XAUTH_PASSWORD_TYPE,
			                              NM_VPNC_PW_TYPE_SAVE);
		} else
			flags |= NM_SETTING_SECRET_FLAG_NOT_SAVED;

		nm_setting_set_secret_flags (NM_SETTING (s_vpn),
			                         NM_VPNC_KEY_XAUTH_PASSWORD,
			                         flags,
			                         NULL);
	}

	if (pcf_file_lookup_string (pcf, "main", "GroupPwd", &buf)) {
		nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_SECRET, buf);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn),
		                             NM_VPNC_KEY_SECRET,
		                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
		                             NULL);
	} else {
		/* Handle encrypted passwords */
		if (pcf_file_lookup_string (pcf, "main", "enc_GroupPwd", &buf)) {
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
		}
	}

	if (pcf_file_lookup_string (pcf, "main", "NTDomain", &buf))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DOMAIN, buf);

	if (pcf_file_lookup_bool (pcf, "main", "SingleDES", &bool_value)) {
		if (bool_value)
			nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_SINGLE_DES, "yes");
	}

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

	if (pcf_file_lookup_bool (pcf, "main", "EnableNat", &bool_value)) {
		if (bool_value) {
			gboolean natt = FALSE, force_natt = FALSE;

			if (!pcf_file_lookup_bool (pcf, "main", "X-NM-Use-NAT-T", &natt))
				natt = FALSE;
			if (!pcf_file_lookup_bool (pcf, "main", "X-NM-Force-NAT-T", &force_natt))
				force_natt = FALSE;

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
		} else {
			nm_setting_vpn_add_data_item (s_vpn,
			                              NM_VPNC_KEY_NAT_TRAVERSAL_MODE,
			                              NM_VPNC_NATT_MODE_NONE);
		}
	}

	if (pcf_file_lookup_int (pcf, "main", "PeerTimeout", &val)) {
		if ((val == 0) || ((val >= 10) && (val <= 86400))) {
			char *tmp = g_strdup_printf ("%d", (gint) val);
			nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DPD_IDLE_TIMEOUT, tmp);
			g_free (tmp);
		}
	}

	if (pcf_file_lookup_bool (pcf, "main", "EnableLocalLAN", &bool_value)) {
		if (bool_value)
			g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_NEVER_DEFAULT, TRUE, NULL);
	}

	if (pcf_file_lookup_string (pcf, "main", "DHGroup", &buf)) {
		if (!strcmp (buf, "1") || !strcmp (buf, "2") || !strcmp (buf, "5")) {
			char *tmp;
			tmp = g_strdup_printf ("dh%s", buf);
			nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DHGROUP, tmp);
			g_free (tmp);
		}
	}

	if (pcf_file_lookup_string (pcf, "main", "X-NM-Routes", &buf))
		add_routes (s_ip4, buf);

	if (pcf_file_lookup_int (pcf, "main", "TunnelingMode", &val)) {
		/* If applicable, put up warning that TCP tunneling will be disabled */

		if (val == 1) {
			GtkWidget *dialog;
			char *basename;

			basename = g_path_get_basename (path);
			dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
			                                 GTK_MESSAGE_WARNING, GTK_BUTTONS_CLOSE,
			                                 _("TCP tunneling not supported"));
			gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
			                                          _("The VPN settings file '%s' specifies that VPN traffic should be tunneled through TCP which is currently not supported in the vpnc software.\n\nThe connection can still be created, with TCP tunneling disabled, however it may not work as expected."), basename);
			g_free (basename);
			gtk_dialog_run (GTK_DIALOG (dialog));
			gtk_widget_destroy (dialog);
		}
	}

	/* UseLegacyIKEPort=0 uses dynamic source IKE port instead of 500.
	 * http://www.cisco.com/en/US/products/sw/secursw/ps2308/products_administration_guide_chapter09186a008015cfdc.html#1192555
	 * See also: http://support.microsoft.com/kb/928310
	 */
	found = pcf_file_lookup_int (pcf, "main", "UseLegacyIKEPort", &val);
	if (!found || val != 0) {
		char *tmp;
		tmp = g_strdup_printf ("%d", (gint) NM_VPNC_LOCAL_PORT_DEFAULT); /* Use default vpnc local port: 500 */
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_LOCAL_PORT, tmp);
		g_free (tmp);
	}

	g_hash_table_destroy (pcf);

	return connection;
}

static gboolean
export (NMVpnPluginUiInterface *iface,
        const char *path,
        NMConnection *connection,
        GError **error)
{
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingVPN *s_vpn;
	FILE *f;
	const char *value;
	const char *gateway = NULL;
	gboolean enablenat = TRUE;
	gboolean singledes = FALSE;
	const char *groupname = NULL;
	const char *username = NULL;
	const char *domain = NULL;
	const char *peertimeout = NULL;
	const char *dhgroup = NULL;
	GString *routes = NULL;
	GString *uselegacyikeport = NULL;
	gboolean success = FALSE;
	guint32 routes_count = 0;
	gboolean save_password = FALSE;
	gboolean use_natt = FALSE;
	gboolean use_force_natt = FALSE;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	f = fopen (path, "w");
	if (!f) {
		g_set_error (error, 0, 0, "could not open file for writing");
		return FALSE;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_GATEWAY);
	if (value && strlen (value))
		gateway = value;
	else {
		g_set_error (error, 0, 0, "connection was incomplete (missing gateway)");
		goto done;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_ID);
	if (value && strlen (value))
		groupname = value;
	else {
		g_set_error (error, 0, 0, "connection was incomplete (missing group)");
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

	routes = g_string_new ("X-NM-Routes=");
	if (s_ip4 && nm_setting_ip4_config_get_num_routes (s_ip4)) {
		int i;

		for (i = 0; i < nm_setting_ip4_config_get_num_routes (s_ip4); i++) {
			NMIP4Route *route = nm_setting_ip4_config_get_route (s_ip4, i);
			char str_addr[INET_ADDRSTRLEN + 1];
			struct in_addr num_addr;

			if (routes_count)
				g_string_append_c (routes, ' ');

			num_addr.s_addr = nm_ip4_route_get_dest (route);
			if (inet_ntop (AF_INET, &num_addr, &str_addr[0], INET_ADDRSTRLEN + 1))
				g_string_append_printf (routes, "%s/%d", str_addr, nm_ip4_route_get_prefix (route));

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
		 "Host=%s\n"
		 "AuthType=1\n"
		 "GroupName=%s\n"
		 "GroupPwd=\n"
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
		 "%s\n",
		 /* Description */   nm_setting_connection_get_id (s_con),
		 /* Host */          gateway,
		 /* GroupName */     groupname,
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
		 /* X-NM-Routes */   (routes && routes->str) ? routes->str : "");

	success = TRUE;

done:
	if (routes)
		g_string_free (routes, TRUE);
	if (uselegacyikeport)
		g_string_free (uselegacyikeport, TRUE);
	fclose (f);
	return success;
}

static char *
get_suggested_name (NMVpnPluginUiInterface *iface, NMConnection *connection)
{
	NMSettingConnection *s_con;
	const char *id;

	g_return_val_if_fail (connection != NULL, NULL);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_return_val_if_fail (s_con != NULL, NULL);

	id = nm_setting_connection_get_id (s_con);
	g_return_val_if_fail (id != NULL, NULL);

	return g_strdup_printf ("%s.pcf", id);
}

static guint32
get_capabilities (NMVpnPluginUiInterface *iface)
{
	return (NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT | NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT);
}

static NMVpnPluginUiWidgetInterface *
ui_factory (NMVpnPluginUiInterface *iface, NMConnection *connection, GError **error)
{
	return nm_vpn_plugin_ui_widget_interface_new (connection, error);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME:
		g_value_set_string (value, VPNC_PLUGIN_NAME);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC:
		g_value_set_string (value, VPNC_PLUGIN_DESC);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE:
		g_value_set_string (value, VPNC_PLUGIN_SERVICE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
vpnc_plugin_ui_class_init (VpncPluginUiClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME,
									  NM_VPN_PLUGIN_UI_INTERFACE_NAME);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC,
									  NM_VPN_PLUGIN_UI_INTERFACE_DESC);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE,
									  NM_VPN_PLUGIN_UI_INTERFACE_SERVICE);
}

static void
vpnc_plugin_ui_init (VpncPluginUi *plugin)
{
}

static void
vpnc_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class)
{
	/* interface implementation */
	iface_class->ui_factory = ui_factory;
	iface_class->get_capabilities = get_capabilities;
	iface_class->import_from_file = import;
	iface_class->export_to_file = export;
	iface_class->get_suggested_name = get_suggested_name;
}


G_MODULE_EXPORT NMVpnPluginUiInterface *
nm_vpn_plugin_ui_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (VPNC_TYPE_PLUGIN_UI, NULL));
}


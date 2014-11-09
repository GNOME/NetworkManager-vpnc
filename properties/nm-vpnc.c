/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * CVSID: $Id: nm-vpnc.c 4366 2008-12-06 00:19:59Z dcbw $
 *
 * nm-vpnc.c : GNOME UI dialogs for configuring vpnc VPN connections
 *
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <glib/gi18n-lib.h>
#include <gtk/gtk.h>

#ifdef NM_VPNC_OLD
#define NM_VPN_LIBNM_COMPAT

#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-ui-utils.h>
#include <nm-vpn-plugin-ui-interface.h>

#define nm_simple_connection_new() nm_connection_new ()

#define NMSettingIPConfig NMSettingIP4Config
#define NM_SETTING_IP_CONFIG(obj) NM_SETTING_IP4_CONFIG (obj)
#define nm_setting_ip_config_get_num_routes nm_setting_ip4_config_get_num_routes
#define nm_setting_ip_config_get_route nm_setting_ip4_config_get_route
#define nm_setting_ip_config_add_route nm_setting_ip4_config_add_route
#define NM_SETTING_IP_CONFIG_NEVER_DEFAULT NM_SETTING_IP4_CONFIG_NEVER_DEFAULT

#define VPNC_PLUGIN_UI_ERROR                  NM_SETTING_VPN_ERROR
#define VPNC_PLUGIN_UI_ERROR_FAILED           NM_SETTING_VPN_ERROR_UNKNOWN
#define VPNC_PLUGIN_UI_ERROR_INVALID_PROPERTY NM_SETTING_VPN_ERROR_INVALID_PROPERTY

#else /* !NM_VPNC_OLD */

#include <NetworkManager.h>
#include <nma-ui-utils.h>

#define VPNC_PLUGIN_UI_ERROR                  NM_CONNECTION_ERROR
#define VPNC_PLUGIN_UI_ERROR_FAILED           NM_CONNECTION_ERROR_FAILED
#define VPNC_PLUGIN_UI_ERROR_INVALID_PROPERTY NM_CONNECTION_ERROR_INVALID_PROPERTY
#endif

#include "nm-vpnc-service-defines.h"
#include "nm-vpnc-helper.h"
#include "nm-vpnc.h"

#define VPNC_PLUGIN_NAME    _("Cisco Compatible VPN (vpnc)")
#define VPNC_PLUGIN_DESC    _("Compatible with various Cisco, Juniper, Netscreen, and Sonicwall IPsec-based VPN gateways.")

#define ENC_TYPE_SECURE 0
#define ENC_TYPE_WEAK   1
#define ENC_TYPE_NONE   2

#define NM_VPNC_LOCAL_PORT_DEFAULT 500

/************** plugin class **************/

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

/************** editor class **************/

static void vpnc_editor_interface_init (NMVpnEditorInterface *iface);

G_DEFINE_TYPE_EXTENDED (VpncEditor, vpnc_editor, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
                                               vpnc_editor_interface_init))

#define VPNC_EDITOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), VPNC_TYPE_EDITOR, VpncEditorPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkSizeGroup *group;
	gint orig_dpd_timeout;
	GtkWidget *advanced_dialog;
} VpncEditorPrivate;


static gboolean
check_validity (VpncEditor *self, GError **error)
{
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (self);
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
	g_signal_emit_by_name (VPNC_EDITOR (user_data), "changed");
}

static void
hybrid_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (user_data);
	gboolean enabled = FALSE;
	GtkWidget *cafile_label, *ca_file_chooser;

	cafile_label = GTK_WIDGET (gtk_builder_get_object (priv->builder, "cafile_label"));
	g_return_if_fail (cafile_label);
	ca_file_chooser = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ca_file_chooser"));
	g_return_if_fail (ca_file_chooser);

	enabled = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));

	gtk_widget_set_sensitive (cafile_label, enabled);
	gtk_widget_set_sensitive (ca_file_chooser, enabled);

	stuff_changed_cb (widget, user_data);
}

static void
spinbutton_changed_cb (GtkWidget *widget, gpointer user_data)
{
	gtk_spin_button_update (GTK_SPIN_BUTTON (widget));

	stuff_changed_cb (widget, user_data);
}

static void
setup_password_widget (VpncEditor *self,
                       const char *entry_name,
                       NMSettingVpn *s_vpn,
                       const char *secret_name,
                       gboolean new_connection)
{
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *value;

	widget = (GtkWidget *) gtk_builder_get_object (priv->builder, entry_name);
	g_assert (widget);
	gtk_size_group_add_widget (priv->group, widget);

	if (s_vpn) {
		value = nm_setting_vpn_get_secret (s_vpn, secret_name);
		gtk_entry_set_text (GTK_ENTRY (widget), value ? value : "");
	}

	g_signal_connect (widget, "changed", G_CALLBACK (stuff_changed_cb), self);
}

static void
show_toggled_cb (GtkCheckButton *button, VpncEditor *self)
{
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (self);
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
password_storage_changed_cb (GObject *entry,
                             GParamSpec *pspec,
                             gpointer user_data)
{
	VpncEditor *self = VPNC_EDITOR (user_data);

	stuff_changed_cb (NULL, self);
}

static const char *
secret_flags_to_pw_type (NMSettingVpn *s_vpn, const char *key)
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
init_password_icon (VpncEditor *self,
                    NMSettingVpn *s_vpn,
                    const char *secret_key,
                    const char *type_key,
                    const char *entry_name)
{
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (self);
	GtkWidget *entry;
	const char *value;
	const char *flags = NULL;

	entry = GTK_WIDGET (gtk_builder_get_object (priv->builder, entry_name));
	g_assert (entry);

	nma_utils_setup_password_storage (entry, 0, (NMSetting *) s_vpn, secret_key,
	                                  TRUE, FALSE);

	/* If there's no password and no flags in the setting,
	 * initialize flags as "always-ask".
	 */
	if (s_vpn) {
		flags = secret_flags_to_pw_type (s_vpn, secret_key);
		if (!flags || !strcmp (flags, NM_VPNC_PW_TYPE_SAVE))
			flags = nm_setting_vpn_get_data_item (s_vpn, type_key);
	}
	value = gtk_entry_get_text (GTK_ENTRY (entry));
	if ((!value || !*value) && !flags)
		nma_utils_update_password_storage (entry, NM_SETTING_SECRET_FLAG_NOT_SAVED,
		                                   (NMSetting *) s_vpn, secret_key);

	g_signal_connect (entry, "notify::secondary-icon-name",
	                  G_CALLBACK (password_storage_changed_cb), self);
}

static void
deinit_password_icon (VpncEditor *self, const char *entry_name)
{
	GtkWidget *entry;

	entry = GTK_WIDGET (gtk_builder_get_object (VPNC_EDITOR_GET_PRIVATE (self)->builder, entry_name));
	g_assert (entry);
	g_signal_handlers_disconnect_by_func (entry, password_storage_changed_cb, self);
}

static void
toggle_advanced_dialog_cb (GtkWidget *button, gpointer user_data)
{
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (user_data);
	GtkWidget *toplevel;

	if (gtk_widget_get_visible (priv->advanced_dialog))
		gtk_widget_hide (priv->advanced_dialog);
	else {
		toplevel = gtk_widget_get_toplevel (priv->widget);
		if (gtk_widget_is_toplevel (toplevel))
			gtk_window_set_transient_for (GTK_WINDOW (priv->advanced_dialog), GTK_WINDOW (toplevel));
		gtk_widget_show_all (priv->advanced_dialog);
	}
}

static const char *
find_tag (const char *tag, const char *buf, gsize len)
{
	gsize i, taglen;

	taglen = strlen (tag);
	if (len < taglen)
		return NULL;

	for (i = 0; i < len - taglen + 1; i++) {
		if (memcmp (buf + i, tag, taglen) == 0)
			return buf + i;
	}
	return NULL;
}

static const char *pem_cert_begin = "-----BEGIN CERTIFICATE-----";

static gboolean
cert_filter (const GtkFileFilterInfo *filter_info, gpointer data)
{
	char *contents = NULL, *p, *ext;
	gsize bytes_read = 0;
	gboolean show = FALSE;
	struct stat statbuf;

	if (!filter_info->filename)
		return FALSE;

	p = strrchr (filter_info->filename, '.');
	if (!p)
		return FALSE;

	ext = g_ascii_strdown (p, -1);
	if (!ext)
		return FALSE;

	if (strcmp (ext, ".pem") && strcmp (ext, ".crt") && strcmp (ext, ".cer")) {
		g_free (ext);
		return FALSE;
	}
	g_free (ext);

	/* Ignore files that are really large */
	if (!stat (filter_info->filename, &statbuf)) {
		if (statbuf.st_size > 500000)
			return FALSE;
	}

	if (!g_file_get_contents (filter_info->filename, &contents, &bytes_read, NULL))
		return FALSE;

	if (bytes_read < 400)  /* needs to be lower? */
		goto out;

	if (find_tag (pem_cert_begin, (const char *) contents, bytes_read)) {
		show = TRUE;
		goto out;
	}

out:
	g_free (contents);
	return show;
}

static gboolean
init_plugin_ui (VpncEditor *self,
                NMConnection *connection,
                gboolean new_connection,
                GError **error)
{
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (self);
	NMSettingConnection *s_con = NULL;
	NMSettingVpn *s_vpn = NULL;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	const char *value = NULL;
	int active = -1;
	const char *natt_mode = NULL;
	const char *ike_dh_group = NULL;
	const char *vendor = NULL;
	const char *pfs_group = NULL;
	gboolean enabled = FALSE;
	GtkFileFilter *filter;

	if (connection) {
		s_con = nm_connection_get_setting_connection (connection);
		s_vpn = nm_connection_get_setting_vpn (connection);
	}

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
	setup_password_widget (self,
	                       "user_password_entry",
	                       s_vpn,
	                       NM_VPNC_KEY_XAUTH_PASSWORD,
	                       new_connection);
	setup_password_widget (self,
	                       "group_password_entry",
	                       s_vpn,
	                       NM_VPNC_KEY_SECRET,
	                       new_connection);

	init_password_icon (self,
	                    s_vpn,
	                    NM_VPNC_KEY_XAUTH_PASSWORD,
	                    NM_VPNC_KEY_XAUTH_PASSWORD_TYPE,
	                    "user_password_entry");
	init_password_icon (self,
	                    s_vpn,
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

	/* Vendor combo */
	active = -1;
	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	if (s_vpn)
		vendor = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_VENDOR);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Cisco (default)"), 1, NM_VPNC_VENDOR_CISCO, -1);
	if ((active < 0) && vendor) {
		if (!strcmp (vendor, NM_VPNC_VENDOR_CISCO))
			active = 0;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Netscreen"), 1, NM_VPNC_VENDOR_NETSCREEN, -1);
	if ((active < 0) && vendor) {
		if (!strcmp (vendor, NM_VPNC_VENDOR_NETSCREEN))
			active = 1;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "vendor_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Application version */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "application_version_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_APP_VERSION);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Interface name */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_name_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_con) {
		value = nm_setting_connection_get_interface_name (s_con);
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

	/* Local Port */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_port_spinbutton"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_LOCAL_PORT);
		if (value) {
			long int tmp;

			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno != 0 || tmp < 0 || tmp > 65535)
				tmp = 0;
			widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_port_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
		}
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (spinbutton_changed_cb), self);

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

	/* Perfect Forward Secrecy combo */
	active = -1;
	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	if (s_vpn)
		pfs_group = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_PERFECT_FORWARD);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Server (default)"), 1, NM_VPNC_PFS_SERVER, -1);
	if ((active < 0) && pfs_group) {
		if (!strcmp (pfs_group, NM_VPNC_PFS_SERVER))
			active = 0;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("None"), 1, NM_VPNC_PFS_NOPFS, -1);
	if ((active < 0) && pfs_group) {
		if (!strcmp (pfs_group, NM_VPNC_PFS_NOPFS))
			active = 1;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 1"), 1, NM_VPNC_PFS_DH1, -1);
	if ((active < 0) && pfs_group) {
		if (!strcmp (pfs_group, NM_VPNC_PFS_DH1))
			active = 2;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 2"), 1, NM_VPNC_PFS_DH2, -1);
	if ((active < 0) && pfs_group) {
		if (!strcmp (pfs_group, NM_VPNC_PFS_DH2))
			active = 3;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 5"), 1, NM_VPNC_PFS_DH5, -1);
	if ((active < 0) && pfs_group) {
		if (!strcmp (pfs_group, NM_VPNC_PFS_DH5))
			active = 4;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "pfsecrecy_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "show_passwords_checkbutton"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "toggled",
	                  (GCallback) show_toggled_cb,
	                  self);

	/* hybrid auth */

	enabled = FALSE;
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hybrid_checkbutton"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_AUTHMODE);
		if (value && !strcmp("hybrid", value)) {
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
			enabled = TRUE;
		}
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (hybrid_toggled_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ca_file_chooser"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, widget);
	gtk_widget_set_sensitive (widget, enabled);
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
	                                   _("Choose a Certificate Authority (CA) certificate..."));

	filter = gtk_file_filter_new ();
	gtk_file_filter_add_custom (filter, GTK_FILE_FILTER_FILENAME, cert_filter, NULL, NULL);
	gtk_file_filter_set_name (filter, _("PEM certificates (*.pem, *.crt, *.cer)"));
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_CA_FILE);
		if (value && strlen (value))
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "file-set", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "cafile_label"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_widget_set_sensitive (widget, enabled);

	/* advanced dialog */

	priv->advanced_dialog = GTK_WIDGET (gtk_builder_get_object (priv->builder, "vpnc-advanced-dialog"));
	g_return_val_if_fail (priv->advanced_dialog != NULL, FALSE);

	g_signal_connect (G_OBJECT (priv->advanced_dialog), "delete-event",
	                  G_CALLBACK (gtk_widget_hide_on_delete), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "advanced_button"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "clicked",
	                  (GCallback) toggle_advanced_dialog_cb,
	                  self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "apply_button"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "clicked",
	                  (GCallback) toggle_advanced_dialog_cb,
	                  self);
	return TRUE;
}

static GObject *
get_widget (NMVpnEditor *editor)
{
	VpncEditor *self = VPNC_EDITOR (editor);
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static void
save_one_password (NMSettingVpn *s_vpn,
                   GtkBuilder *builder,
                   const char *entry_name,
                   const char *secret_key,
                   const char *type_key)
{
	NMSettingSecretFlags flags;
	const char *data_val = NULL, *password;
	GtkWidget *entry;

	/* Get secret flags */
	entry = GTK_WIDGET (gtk_builder_get_object (builder, entry_name));
	flags = nma_utils_menu_to_secret_flags (entry);

	/* Save password and convert flags to legacy data items */
	switch (flags) {
	case NM_SETTING_SECRET_FLAG_NONE:
	case NM_SETTING_SECRET_FLAG_AGENT_OWNED:
		password = gtk_entry_get_text (GTK_ENTRY (entry));
		if (password && strlen (password))
			nm_setting_vpn_add_secret (s_vpn, secret_key, password);
		data_val = NM_VPNC_PW_TYPE_SAVE;
		break;
	case NM_SETTING_SECRET_FLAG_NOT_REQUIRED:
		data_val = NM_VPNC_PW_TYPE_UNUSED;
		break;
	case NM_SETTING_SECRET_FLAG_NOT_SAVED:
	default:
		data_val = NM_VPNC_PW_TYPE_ASK;
		break;
	}

	/* Set both new secret flags and old data item for backwards compat */
	nm_setting_vpn_add_data_item (s_vpn, type_key, data_val);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), secret_key, flags, NULL);
}

static gboolean
update_connection (NMVpnEditor *editor,
                   NMConnection *connection,
                   GError **error)
{
	VpncEditor *self = VPNC_EDITOR (editor);
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	char *str;
	guint32 port;
	GtkTreeModel *model;
	GtkTreeIter iter;

	if (!check_validity (self, error))
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_VPNC, NULL);

	/* Interface name */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_name_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_INTERFACE_NAME, str, NULL);

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

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "vendor_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		const char *vendor = NULL;

		gtk_tree_model_get (model, &iter, 1, &vendor, -1);
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_VENDOR, vendor);
	} else
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_VENDOR, NM_VPNC_VENDOR_CISCO);

	/* Application version */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "application_version_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_APP_VERSION, str);

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

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "pfsecrecy_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		const char *pfs = NULL;

		gtk_tree_model_get (model, &iter, 1, &pfs, -1);
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_PERFECT_FORWARD, pfs);
	} else
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_PERFECT_FORWARD, NM_VPNC_PFS_SERVER);

	/* Local port */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_port_spinbutton"));
	port = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
	nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_LOCAL_PORT, g_strdup_printf ("%d", port));

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

	/* User password */
	save_one_password (s_vpn,
	                   priv->builder,
	                   "user_password_entry",
	                   NM_VPNC_KEY_XAUTH_PASSWORD,
	                   NM_VPNC_KEY_XAUTH_PASSWORD_TYPE);

	/* Group password */
	save_one_password (s_vpn,
	                   priv->builder,
	                   "group_password_entry",
	                   NM_VPNC_KEY_SECRET,
	                   NM_VPNC_KEY_SECRET_TYPE);

	/* hybrid auth */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "hybrid_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_AUTHMODE, "hybrid");

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ca_file_chooser"));
	str = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_CA_FILE, str);

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

static NMVpnEditor *
nm_vpnc_editor_new (NMConnection *connection, GError **error)
{
	NMVpnEditor *object;
	VpncEditorPrivate *priv;
	char *ui_file;
	NMSettingVpn *s_vpn;
	gboolean is_new = TRUE;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = g_object_new (VPNC_TYPE_EDITOR, NULL);
	if (!object) {
		g_set_error (error, VPNC_PLUGIN_UI_ERROR, VPNC_PLUGIN_UI_ERROR_FAILED,
		             "could not create vpnc object");
		return NULL;
	}

	priv = VPNC_EDITOR_GET_PRIVATE (object);

	ui_file = g_strdup_printf ("%s/%s", UIDIR, "nm-vpnc-dialog.ui");
	priv->builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_file (priv->builder, ui_file, error)) {
		g_warning ("Couldn't load builder file: %s",
		           error && *error ? (*error)->message : "(unknown)");
		g_clear_error (error);
		g_set_error (error, VPNC_PLUGIN_UI_ERROR, VPNC_PLUGIN_UI_ERROR_FAILED,
		             "could not load required resources at %s", ui_file);
		g_free (ui_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (ui_file);

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "vpnc-vbox"));
	if (!priv->widget) {
		g_set_error (error, VPNC_PLUGIN_UI_ERROR, VPNC_PLUGIN_UI_ERROR_FAILED,
		             "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		nm_setting_vpn_foreach_data_item (s_vpn, is_new_func, &is_new);

	if (!init_plugin_ui (VPNC_EDITOR (object), connection, is_new, error)) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	VpncEditor *plugin = VPNC_EDITOR (object);
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (plugin);

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->advanced_dialog)
		gtk_widget_destroy (priv->advanced_dialog);

	if (priv->builder) {
		deinit_password_icon (plugin, "user_password_entry");
		deinit_password_icon (plugin, "group_password_entry");
		g_object_unref (priv->builder);
	}

	G_OBJECT_CLASS (vpnc_editor_parent_class)->dispose (object);
}

static void
vpnc_editor_class_init (VpncEditorClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (VpncEditorPrivate));

	object_class->dispose = dispose;
}

static void
vpnc_editor_init (VpncEditor *plugin)
{
}

static void
vpnc_editor_interface_init (NMVpnEditorInterface *iface)
{
	/* interface implementation */
	iface->get_widget = get_widget;
	iface->update_connection = update_connection;
}

static void
add_routes (NMSettingIPConfig *s_ip4, const char *routelist)
{
	char **substrs;
	unsigned int i;

	substrs = g_strsplit (routelist, " ", 0);
	for (i = 0; substrs[i] != NULL; i++) {
		char *p, *str_route;
		long int prefix = 32;
#ifdef NM_VPNC_OLD
		struct in_addr tmp;
#else
		NMIPRoute *route;
		GError *error = NULL;
#endif

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

#ifdef NM_VPNC_OLD
		if (inet_pton (AF_INET, str_route, &tmp) > 0) {
			NMIP4Route *route = nm_ip4_route_new ();

			nm_ip4_route_set_dest (route, tmp.s_addr);
			nm_ip4_route_set_prefix (route, (guint32) prefix);

			nm_setting_ip_config_add_route (s_ip4, route);
		} else
			g_warning ("Ignoring invalid route '%s'", str_route);
#else
		route = nm_ip_route_new (AF_INET, str_route, prefix, NULL, -1, &error);
		if (route) {
			nm_setting_ip_config_add_route (s_ip4, route);
			nm_ip_route_unref (route);
		} else {
			g_warning ("Ignoring invalid route '%s': %s", str_route, error->message);
			g_clear_error (&error);
		}
#endif

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
	buf = key_file_get_string_helper (keyfile, "main", "InterfaceName", NULL);
	if (buf) {
		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_INTERFACE_NAME, buf, NULL);
		g_free (buf);
	}

	/* Gateway */
	buf = key_file_get_string_helper (keyfile, "main", "Host", NULL);
	if (buf) {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_GATEWAY, buf);
		g_free (buf);
	} else {
		g_set_error (error,
		             NM_VPNC_IMPORT_EXPORT_ERROR,
		             NM_VPNC_IMPORT_EXPORT_ERROR_NOT_VPNC,
		             "does not look like a %s VPN connection (no Host)",
		             VPNC_PLUGIN_NAME);
		goto error;
	}

	/* Group name */
	buf = key_file_get_string_helper (keyfile, "main", "GroupName", NULL);
	if (buf) {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_ID, buf);
		g_free (buf);
	} else {
		g_set_error (error,
		             NM_VPNC_IMPORT_EXPORT_ERROR,
		             NM_VPNC_IMPORT_EXPORT_ERROR_BAD_DATA,
		             "does not look like a %s VPN connection (no GroupName)",
		             VPNC_PLUGIN_NAME);
		goto error;
	}

	/* Optional settings */

	/* Connection name */
	buf = key_file_get_string_helper (keyfile, "main", "Description", NULL);
	if (buf) {
		g_object_set (s_con, NM_SETTING_CONNECTION_ID, buf, NULL);
		g_free (buf);
	}

	buf = key_file_get_string_helper (keyfile, "main", "Username", NULL);
	if (buf) {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER, buf);
		g_free (buf);
	}

	buf = key_file_get_string_helper (keyfile, "main", "UserPassword", NULL);
	if (buf) {
		nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD, buf);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn),
		                             NM_VPNC_KEY_XAUTH_PASSWORD,
		                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
		                             NULL);
		g_free (buf);
	}

	bool_value = key_file_get_boolean_helper (keyfile, "main", "SaveUserPassword", NULL);
	flags = NM_SETTING_SECRET_FLAG_AGENT_OWNED;
	if (bool_value) {
		nm_setting_vpn_add_data_item (s_vpn,
		                              NM_VPNC_KEY_XAUTH_PASSWORD_TYPE,
		                              NM_VPNC_PW_TYPE_SAVE);
	} else {
		flags |= NM_SETTING_SECRET_FLAG_NOT_SAVED;
	}
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_VPNC_KEY_XAUTH_PASSWORD, flags, NULL);

	buf = key_file_get_string_helper (keyfile, "main", "GroupPwd", NULL);
	if (buf) {
		nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_SECRET, buf);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn),
		                             NM_VPNC_KEY_SECRET,
		                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
		                             NULL);
		g_free (buf);
	} else {
		/* Handle encrypted passwords */
		buf = key_file_get_string_helper (keyfile, "main", "enc_GroupPwd", NULL);
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

		bool_value = key_file_get_boolean_helper (keyfile, "main", "X-NM-SaveGroupPassword", NULL);
		if (bool_value) {
			nm_setting_vpn_add_data_item (s_vpn,
			                              NM_VPNC_KEY_SECRET_TYPE,
			                              NM_VPNC_PW_TYPE_SAVE);
		} else {
			flags |= NM_SETTING_SECRET_FLAG_NOT_SAVED;
		}

		nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_VPNC_KEY_SECRET, flags, NULL);
	} else {
		/* If the key isn't present, assume "saved" */
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_SECRET_TYPE, NM_VPNC_PW_TYPE_SAVE);
	}

	buf = key_file_get_string_helper (keyfile, "main", "NTDomain", NULL);
	if (buf) {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DOMAIN, buf);
		g_free (buf);
	}

	bool_value = key_file_get_boolean_helper (keyfile, "main", "SingleDES", NULL);
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

	bool_value = key_file_get_boolean_helper (keyfile, "main", "EnableNat", NULL);
	if (bool_value) {
		gboolean natt = FALSE;
		gboolean force_natt = FALSE;

		natt = key_file_get_boolean_helper (keyfile, "main", "X-NM-Use-NAT-T", NULL);
		force_natt = key_file_get_boolean_helper (keyfile, "main", "X-NM-Force-NAT-T", NULL);

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

	bool_value = key_file_get_boolean_helper (keyfile, "main", "EnableLocalLAN", NULL);
	if (bool_value)
		g_object_set (s_ip4, NM_SETTING_IP_CONFIG_NEVER_DEFAULT, TRUE, NULL);

	buf = key_file_get_string_helper (keyfile, "main", "DHGroup", NULL);
	if (buf) {
		if (!strcmp (buf, "1") || !strcmp (buf, "2") || !strcmp (buf, "5")) {
			char *tmp;
			tmp = g_strdup_printf ("dh%s", buf);
			nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DHGROUP, tmp);
			g_free (tmp);
		}
		g_free (buf);
	}

	buf = key_file_get_string_helper (keyfile, "main", "X-NM-Routes", NULL);
	if (buf) {
		add_routes (s_ip4, buf);
		g_free (buf);
	}

	if (key_file_get_integer_helper (keyfile, "main", "TunnelingMode", &val)) {
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
#ifdef NM_VPNC_OLD
			NMIP4Route *route = nm_setting_ip_config_get_route (s_ip4, i);
			char str_addr[INET_ADDRSTRLEN + 1];
			struct in_addr num_addr;
#else
			NMIPRoute *route = nm_setting_ip_config_get_route (s_ip4, i);
#endif

			if (routes_count)
				g_string_append_c (routes, ' ');
#ifdef NM_VPNC_OLD
			num_addr.s_addr = nm_ip4_route_get_dest (route);
			if (inet_ntop (AF_INET, &num_addr, &str_addr[0], INET_ADDRSTRLEN + 1))
				g_string_append_printf (routes, "%s/%d", str_addr, nm_ip4_route_get_prefix (route));
#else
			g_string_append_printf (routes, "%s/%d",
			                        nm_ip_route_get_dest (route),
			                        nm_ip_route_get_prefix (route));
#endif

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
get_editor (NMVpnEditorPlugin *plugin, NMConnection *connection, GError **error)
{
	return nm_vpnc_editor_new (connection, error);
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
vpnc_editor_plugin_init (VpncEditorPlugin *plugin)
{
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


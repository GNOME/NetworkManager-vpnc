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

#include "nm-default.h"

#include "nm-vpnc-editor.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gtk/gtk.h>

#include "nm-vpnc-helper.h"

#define ENC_TYPE_SECURE 0
#define ENC_TYPE_WEAK   1
#define ENC_TYPE_NONE   2

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
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_VPNC_KEY_GATEWAY);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
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

static void
vpnc_editor_init (VpncEditor *plugin)
{
}

NMVpnEditor *
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
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, NMV_EDITOR_PLUGIN_ERROR_FAILED,
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
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, NMV_EDITOR_PLUGIN_ERROR_FAILED,
		             "could not load required resources at %s", ui_file);
		g_free (ui_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (ui_file);

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "vpnc-vbox"));
	if (!priv->widget) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, NMV_EDITOR_PLUGIN_ERROR_FAILED,
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
vpnc_editor_interface_init (NMVpnEditorInterface *iface)
{
	/* interface implementation */
	iface->get_widget = get_widget;
	iface->update_connection = update_connection;
}


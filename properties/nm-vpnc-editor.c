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
#include "nm-vpnc-editor-plugin.h"

#include <nma-cert-chooser.h>
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

#if !GTK_CHECK_VERSION(4,0,0)
#define gtk_editable_set_text(editable,text)		gtk_entry_set_text(GTK_ENTRY(editable), (text))
#define gtk_editable_get_text(editable)			gtk_entry_get_text(GTK_ENTRY(editable))
#define gtk_widget_get_root(widget)			gtk_widget_get_toplevel(widget)
#define gtk_check_button_get_active(button)		gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button))
#define gtk_check_button_set_active(button, active)	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(button), active)
#define gtk_window_destroy(window)			gtk_widget_destroy(GTK_WIDGET (window))
#define gtk_window_set_hide_on_close(window, hide)						\
	G_STMT_START {										\
		G_STATIC_ASSERT(hide);								\
		g_signal_connect_swapped (G_OBJECT (window), "delete-event",			\
		                          G_CALLBACK (gtk_widget_hide_on_delete), window);	\
	} G_STMT_END

typedef void GtkRoot;
#endif

static void vpnc_editor_interface_init (NMVpnEditorInterface *iface);

G_DEFINE_TYPE_EXTENDED (VpncEditor, vpnc_editor, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
                                               vpnc_editor_interface_init))

#define VPNC_EDITOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), VPNC_TYPE_EDITOR, VpncEditorPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	gint orig_dpd_timeout;
	GtkWidget *advanced_dialog;

	NMSettingVpn *s_vpn;
	char *interface_name;
} VpncEditorPrivate;


static gboolean
check_validity (VpncEditor *self, GError **error)
{
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	char *str;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = (char *) gtk_editable_get_text (GTK_EDITABLE (widget));
	if (!str || !strlen (str) || strstr (str, " ") || strstr (str, "\t")) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_VPNC_KEY_GATEWAY);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
	str = (char *) gtk_editable_get_text (GTK_EDITABLE (widget));
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
	GtkWidget *ca_chooser;

	ca_chooser = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ca_chooser"));
	g_return_if_fail (ca_chooser);

	enabled = gtk_check_button_get_active (GTK_CHECK_BUTTON (widget));

	gtk_widget_set_sensitive (ca_chooser, enabled);

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

	if (s_vpn) {
		value = nm_setting_vpn_get_secret (s_vpn, secret_name);
		gtk_editable_set_text (GTK_EDITABLE (widget), value ? value : "");
	}

	g_signal_connect (widget, "changed", G_CALLBACK (stuff_changed_cb), self);
}

static void
show_toggled_cb (GtkCheckButton *button, VpncEditor *self)
{
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	gboolean visible;

	visible = gtk_check_button_get_active (GTK_CHECK_BUTTON (button));

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
	value = gtk_editable_get_text (GTK_EDITABLE (entry));
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
populate_adv_dialog (VpncEditor *self)
{
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (self);
	const char *value = NULL;
	GtkWidget *widget;
	int active;

	/* Domain */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "domain_entry"));
	g_return_if_fail (widget != NULL);
	value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_DOMAIN);
	if (!value)
		value = "";
	gtk_editable_set_text (GTK_EDITABLE (widget), value);

	/* Vendor combo */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "vendor_combo"));
	value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_VENDOR);
	if (!value)
		value = "";
	active = -1;
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_VENDOR_CISCO))
			active = 0;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_VENDOR_NETSCREEN))
			active = 1;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_VENDOR_FORTIGATE))
			active = 2;
	}
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active == -1 ? 0 : active);

	/* Application version */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "application_version_entry"));
	g_return_if_fail (widget != NULL);
	value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_APP_VERSION);
	if (!value)
		value = "";
	gtk_editable_set_text (GTK_EDITABLE (widget), value);

	/* Interface name */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_name_entry"));
	g_return_if_fail (widget != NULL);
	if (priv->interface_name)
		gtk_editable_set_text (GTK_EDITABLE (widget), priv->interface_name);

	/* Encryption combo */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "encryption_combo"));
	g_return_if_fail (widget != NULL);
	active = -1;
	if (active == -1) {
		value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_SINGLE_DES);
		if (value && !strcmp (value, "yes"))
			active = 1;
	}
	if (active == -1) {
		value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_NO_ENCRYPTION);
		if (value && !strcmp (value, "yes"))
			active = 2;
	}
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active == -1 ? 0 : active);

	/* NAT Traversal */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "natt_combo"));
	g_return_if_fail (widget != NULL);
	value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	active = -1;
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_NATT_MODE_NATT))
			active = 0;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_NATT_MODE_NATT_ALWAYS))
			active = 1;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_NATT_MODE_CISCO))
			active = 2;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_NATT_MODE_NONE))
			active = 3;
	}
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active == -1 ? 0 : active);

	/* DH group */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "dhgroup_combo"));
	g_return_if_fail (widget != NULL);
	value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_DHGROUP);
	active = -1;
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_DHGROUP_DH1))
			active = 0;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_DHGROUP_DH2))
			active = 1;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_DHGROUP_DH5))
			active = 2;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_DHGROUP_DH14))
			active = 3;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_DHGROUP_DH15))
			active = 4;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_DHGROUP_DH16))
			active = 5;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_DHGROUP_DH17))
			active = 6;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_DHGROUP_DH18))
			active = 7;
	}
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active == -1 ? 1 : active);

	/* Perfect Forward Secrecy combo */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "pfsecrecy_combo"));
	g_return_if_fail (widget != NULL);
	active = -1;
	value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_PERFECT_FORWARD);
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_PFS_SERVER))
			active = 0;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_PFS_NOPFS))
			active = 1;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_PFS_DH1))
			active = 2;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_PFS_DH2))
			active = 3;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_PFS_DH5))
			active = 4;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_PFS_DH14))
			active = 5;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_PFS_DH15))
			active = 6;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_PFS_DH16))
			active = 7;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_PFS_DH17))
			active = 8;
	}
	if ((active == -1) && value) {
		if (!strcmp (value, NM_VPNC_PFS_DH18))
			active = 9;
	}
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active == -1 ? 0 : active);

	/* Local Port */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_port_spinbutton"));
	g_return_if_fail (widget != NULL);
	value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_LOCAL_PORT);
	if (value) {
		long int tmp;

		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno != 0 || tmp < 0 || tmp > 65535)
			tmp = 0;
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_port_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
	} else {
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 0);
	}

	/* Disable DPD */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "disable_dpd_checkbutton"));
	g_return_if_fail (widget != NULL);
	value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_DPD_IDLE_TIMEOUT);
	if (value && priv->orig_dpd_timeout == 0)
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

	/* Interface MTU */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_mtu_entry"));
	g_return_if_fail (widget != NULL);
	value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_MTU);
	if (value)
		gtk_editable_set_text (GTK_EDITABLE (widget), value);

	/* Weak Authentication */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "weak_authentication_checkbutton"));
	g_return_if_fail (widget != NULL);
	value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_WEAK_AUTH);
	if (value && !strcmp(value, "yes"))
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

	/* Weak Encryption */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "weak_encryption_checkbutton"));
	g_return_if_fail (widget != NULL);
	value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_WEAK_ENCRYPT);
	if (value && !strcmp(value, "yes"))
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
}

static void
update_adv_settings (VpncEditor *self, NMSettingVpn *s_vpn)
{
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (self);
	const char *value = NULL;
	GtkTreeModel *model;
	GtkWidget *widget;
	GtkTreeIter iter;
	guint32 port;

	/* Domain */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "domain_entry"));
	value = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (value && strlen (value))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DOMAIN, value);
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_VPNC_KEY_DOMAIN);

	/* Vendor combo */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "vendor_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		const char *vendor = NULL;

		gtk_tree_model_get (model, &iter, 1, &vendor, -1);
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_VENDOR, vendor);
	} else {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_VENDOR, NM_VPNC_VENDOR_CISCO);
	}

	/* Application version */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "application_version_entry"));
	value = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (value && strlen (value))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_APP_VERSION, value);
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_VPNC_KEY_APP_VERSION);

	/* Interface name */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_name_entry"));
	value = gtk_editable_get_text (GTK_EDITABLE (widget));
	g_clear_pointer (&priv->interface_name, g_free);
	priv->interface_name = g_strdup (value);

	/* Encryption combo */
	nm_setting_vpn_remove_data_item (s_vpn, NM_VPNC_KEY_SINGLE_DES);
	nm_setting_vpn_remove_data_item (s_vpn, NM_VPNC_KEY_NO_ENCRYPTION);
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

	/* NAT Traversal */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "natt_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		const char *mode = NULL;

		gtk_tree_model_get (model, &iter, 1, &mode, -1);
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE, mode);
	} else {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE, NM_VPNC_NATT_MODE_NATT);
	}

	/* DH group */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "dhgroup_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		const char *dhgroup = NULL;

		gtk_tree_model_get (model, &iter, 1, &dhgroup, -1);
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DHGROUP, dhgroup);
	} else {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DHGROUP, NM_VPNC_DHGROUP_DH2);
	}

	/* Perfect Forward Secrecy combo */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "pfsecrecy_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		const char *pfs = NULL;

		gtk_tree_model_get (model, &iter, 1, &pfs, -1);
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_PERFECT_FORWARD, pfs);
	} else {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_PERFECT_FORWARD, NM_VPNC_PFS_SERVER);
	}

	/* Local port */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_port_spinbutton"));
	port = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
	nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_LOCAL_PORT, g_strdup_printf ("%d", port));

	/* Disable DPD */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "disable_dpd_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
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

	/* Interface MTU */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "interface_mtu_entry"));
	value = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (value && strlen (value))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_MTU, value);
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_VPNC_KEY_MTU);

	/* Weak Authentication */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "weak_authentication_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_WEAK_AUTH, "yes");

	/* Weak Encryption */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "weak_encryption_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_WEAK_ENCRYPT, "yes");
}

static void
advanced_dialog_response_cb (GtkWidget *dialog, gint response, gpointer user_data)
{
	VpncEditor *self = VPNC_EDITOR (user_data);
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (self);

	gtk_widget_hide (priv->advanced_dialog);
	gtk_window_set_transient_for (GTK_WINDOW (priv->advanced_dialog), NULL);

	if (response == GTK_RESPONSE_APPLY) {
		update_adv_settings (self, priv->s_vpn);
		stuff_changed_cb (dialog, self);
	} else {
		populate_adv_dialog (self);
	}
}

static void
advanced_button_clicked_cb (GtkWidget *button, gpointer user_data)
{
	VpncEditorPrivate *priv = VPNC_EDITOR_GET_PRIVATE (user_data);
	GtkRoot *root;

	root = gtk_widget_get_root (priv->widget);
	if (GTK_IS_WINDOW(root))
		gtk_window_set_transient_for (GTK_WINDOW (priv->advanced_dialog), GTK_WINDOW (root));
	gtk_widget_show (priv->advanced_dialog);
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
	gboolean enabled = FALSE;

	if (connection) {
		s_con = nm_connection_get_setting_connection (connection);
		s_vpn = nm_connection_get_setting_vpn (connection);
	}

	if (s_vpn)
		priv->s_vpn = NM_SETTING_VPN (nm_setting_duplicate (NM_SETTING (s_vpn)));
	else
		priv->s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());

	/* Gateway */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_GATEWAY);
		if (value && strlen (value))
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Group */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_ID);
		if (value && strlen (value))
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Encryption combo */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "encryption_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);

	store = gtk_list_store_new (1, G_TYPE_STRING);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Secure (default)"), -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Weak (use with caution)"), -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("None (completely insecure)"), -1);

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);

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

	/* User name */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER);
		if (value && strlen (value))
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Vendor combo */
	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Cisco (default)"), 1, NM_VPNC_VENDOR_CISCO, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Netscreen"), 1, NM_VPNC_VENDOR_NETSCREEN, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Fortigate"), 1, NM_VPNC_VENDOR_FORTIGATE, -1);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "vendor_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);

	/* NAT Traversal */
	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("NAT-T when available (default)"), 1, NM_VPNC_NATT_MODE_NATT, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("NAT-T always"), 1, NM_VPNC_NATT_MODE_NATT_ALWAYS, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Cisco UDP"), 1, NM_VPNC_NATT_MODE_CISCO, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Disabled"), 1, NM_VPNC_NATT_MODE_NONE, -1);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "natt_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);

	/* DH group */
	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 1"), 1, NM_VPNC_DHGROUP_DH1, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 2 (default)"), 1, NM_VPNC_DHGROUP_DH2, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 5"), 1, NM_VPNC_DHGROUP_DH5, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 14"), 1, NM_VPNC_DHGROUP_DH14, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 15"), 1, NM_VPNC_DHGROUP_DH15, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 16"), 1, NM_VPNC_DHGROUP_DH16, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 17"), 1, NM_VPNC_DHGROUP_DH17, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 18"), 1, NM_VPNC_DHGROUP_DH18, -1);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "dhgroup_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);

	/* Perfect Forward Secrecy combo */
	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Server (default)"), 1, NM_VPNC_PFS_SERVER, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("None"), 1, NM_VPNC_PFS_NOPFS, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 1"), 1, NM_VPNC_PFS_DH1, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 2"), 1, NM_VPNC_PFS_DH2, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 5"), 1, NM_VPNC_PFS_DH5, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 14"), 1, NM_VPNC_PFS_DH14, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 15"), 1, NM_VPNC_PFS_DH15, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 16"), 1, NM_VPNC_PFS_DH16, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 17"), 1, NM_VPNC_PFS_DH17, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("DH Group 18"), 1, NM_VPNC_PFS_DH18, -1);


	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "pfsecrecy_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);

	/* Show passwords */
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
			gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
			enabled = TRUE;
		}
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (hybrid_toggled_cb), self);

	/* CA Certificate */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ca_chooser"));
	g_return_val_if_fail (widget, FALSE);
	nma_cert_chooser_add_to_size_group (NMA_CERT_CHOOSER (widget),
		GTK_SIZE_GROUP (gtk_builder_get_object (priv->builder, "labels")));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);
	gtk_widget_set_sensitive (widget, enabled);

	/* Local port */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_port_spinbutton"));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (gtk_spin_button_update), self);

	/* Advanced dialog */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "disable_dpd_checkbutton"));
	g_return_val_if_fail (widget != NULL, FALSE);
	value = nm_setting_vpn_get_data_item (priv->s_vpn, NM_VPNC_KEY_DPD_IDLE_TIMEOUT);
	if (value) {
		long int tmp;

		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (tmp >= 0 && tmp <= G_MAXUINT32 && errno == 0)
			priv->orig_dpd_timeout = (guint32) tmp;
	}
	if (s_con) {
		value = nm_setting_connection_get_interface_name (s_con);
		priv->interface_name = g_strdup (value);
	}
	populate_adv_dialog (self);

	priv->advanced_dialog = GTK_WIDGET (gtk_builder_get_object (priv->builder, "vpnc-advanced-dialog"));
	g_return_val_if_fail (priv->advanced_dialog != NULL, FALSE);

	gtk_window_set_hide_on_close (GTK_WINDOW (priv->advanced_dialog), TRUE);

        g_signal_connect (G_OBJECT (priv->advanced_dialog), "response",
                          G_CALLBACK (advanced_dialog_response_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "advanced_button"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "clicked",
	                  (GCallback) advanced_button_clicked_cb,
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
		password = gtk_editable_get_text (GTK_EDITABLE (entry));
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

	if (!check_validity (self, error))
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_VPNC, NULL);

	/* Gateway */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = (char *) gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_GATEWAY, str);

	/* Group name */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
	str = (char *) gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_ID, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
	str = (char *) gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER, str);

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
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_AUTHMODE, "hybrid");

		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ca_chooser"));
		str = nma_cert_chooser_get_cert (NMA_CERT_CHOOSER (widget), NULL);
		if (str && str[0])
			nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_CA_FILE, str);
	}

	/* Advanced dialog */
	update_adv_settings (self, s_vpn);

	str = priv->interface_name;
	if (str && strlen (str))
		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_INTERFACE_NAME, str, NULL);

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

	priv->builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_resource (priv->builder, "/org/freedesktop/network-manager-vpnc/nm-vpnc-dialog.ui", error)) {
		g_warning ("Couldn't load builder file: %s",
		           error && *error ? (*error)->message : "(unknown)");
		g_object_unref (object);
		return NULL;
	}

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

	g_clear_pointer (&priv->interface_name, g_free);
	g_clear_object (&priv->s_vpn);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->advanced_dialog)
		gtk_window_destroy (GTK_WINDOW (priv->advanced_dialog));

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

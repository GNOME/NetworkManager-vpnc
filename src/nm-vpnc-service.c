/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * (C) Copyright 2005 - 2010 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>

#include <nm-setting-vpn.h>
#include "nm-vpnc-service.h"
#include "nm-utils.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

static gboolean debug = FALSE;
static GMainLoop *loop = NULL;

G_DEFINE_TYPE (NMVPNCPlugin, nm_vpnc_plugin, NM_TYPE_VPN_PLUGIN)

typedef struct {
	GPid pid;
} NMVPNCPluginPrivate;

#define NM_VPNC_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPNC_PLUGIN, NMVPNCPluginPrivate))

static const char *vpnc_binary_paths[] =
{
	"/usr/sbin/vpnc",
	"/sbin/vpnc",
	"/usr/local/sbin/vpnc",
	NULL
};

#define NM_VPNC_HELPER_PATH		LIBEXECDIR"/nm-vpnc-service-vpnc-helper"
#define NM_VPNC_UDP_ENCAPSULATION_PORT	0 /* random port */
#define NM_VPNC_LOCAL_PORT_ISAKMP	0 /* random port */

typedef struct {
	const char *name;
	GType type;
	gint int_min;
	gint int_max;
} ValidProperty;

#define LEGACY_NAT_KEEPALIVE "NAT-Keepalive packet interval"

static ValidProperty valid_properties[] = {
	{ NM_VPNC_KEY_GATEWAY,               G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_ID,                    G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_XAUTH_USER,            G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_DOMAIN,                G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_DHGROUP,               G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_PERFECT_FORWARD,       G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_VENDOR,                G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_APP_VERSION,           G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_SINGLE_DES,            G_TYPE_BOOLEAN, 0, 0 },
	{ NM_VPNC_KEY_NO_ENCRYPTION,         G_TYPE_BOOLEAN, 0, 0 },
	{ NM_VPNC_KEY_DPD_IDLE_TIMEOUT,      G_TYPE_INT, 0, 86400 },
	{ NM_VPNC_KEY_NAT_TRAVERSAL_MODE,    G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_CISCO_UDP_ENCAPS_PORT, G_TYPE_INT, 0, 65535 },
	{ NM_VPNC_KEY_LOCAL_PORT,            G_TYPE_INT, 0, 65535 },
	/* Ignored option for internal use */
	{ NM_VPNC_KEY_SECRET_TYPE,           G_TYPE_NONE, 0, 0 },
	{ NM_VPNC_KEY_XAUTH_PASSWORD_TYPE,   G_TYPE_NONE, 0, 0 },
	/* Legacy options that are ignored */
	{ LEGACY_NAT_KEEPALIVE,              G_TYPE_STRING, 0, 0 },
	{ NULL,                              G_TYPE_NONE, 0, 0 }
};

static ValidProperty valid_secrets[] = {
	{ NM_VPNC_KEY_SECRET,                G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_XAUTH_PASSWORD,        G_TYPE_STRING, 0, 0 },
	{ NULL,                              G_TYPE_NONE, 0, 0 }
};

typedef struct ValidateInfo {
	ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		ValidProperty prop = info->table[i];
		long int tmp;

		if (strcmp (prop.name, key))
			continue;

		switch (prop.type) {
		case G_TYPE_NONE:
			return; /* technically valid, but unused */
		case G_TYPE_STRING:
			return; /* valid */
		case G_TYPE_INT:
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0 && tmp >= prop.int_min && tmp <= prop.int_max)
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "invalid integer property '%s' or out of range [%d -> %d]",
			             key, prop.int_min, prop.int_max);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "invalid boolean property '%s' (not yes or no)",
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "unhandled property '%s' type %s",
			             key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "property '%s' invalid or not supported",
		             key);
	}
}

static gboolean
nm_vpnc_properties_validate (NMSettingVPN *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_properties[0], error, FALSE };

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "No VPN configuration options.");
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

static gboolean
nm_vpnc_secrets_validate (NMSettingVPN *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_secrets[0], error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "No VPN secrets!");
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

static void
vpnc_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMVPNCPlugin *plugin = NM_VPNC_PLUGIN (user_data);
	NMVPNCPluginPrivate *priv = NM_VPNC_PLUGIN_GET_PRIVATE (plugin);
	guint error = 0;

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			nm_warning ("vpnc exited with error code %d", error);
	}
	else if (WIFSTOPPED (status))
		nm_warning ("vpnc stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		nm_warning ("vpnc died with signal %d", WTERMSIG (status));
	else
		nm_warning ("vpnc died from an unknown cause");

	/* Reap child if needed. */
	waitpid (priv->pid, NULL, WNOHANG);
	priv->pid = 0;

	/* Must be after data->state is set since signals use data->state */
	switch (error) {
	case 2:
		/* Couldn't log in due to bad user/pass */
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
		break;
	case 1:
		/* Other error (couldn't bind to address, etc) */
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		break;
	}

	nm_vpn_plugin_set_state (NM_VPN_PLUGIN (plugin), NM_VPN_SERVICE_STATE_STOPPED);
}

static gint
nm_vpnc_start_vpnc_binary (NMVPNCPlugin *plugin, GError **error)
{
	GPid	pid;
	const char **vpnc_binary = NULL;
	GPtrArray *vpnc_argv;
	GSource *vpnc_watch;
	gint	stdin_fd;

	/* Find vpnc */
	vpnc_binary = vpnc_binary_paths;
	while (*vpnc_binary != NULL) {
		if (g_file_test (*vpnc_binary, G_FILE_TEST_EXISTS))
			break;
		vpnc_binary++;
	}

	if (!*vpnc_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             "Could not find vpnc binary.");
		return -1;
	}

	vpnc_argv = g_ptr_array_new ();
	g_ptr_array_add (vpnc_argv, (gpointer) (*vpnc_binary));
	g_ptr_array_add (vpnc_argv, (gpointer) "--non-inter");
	g_ptr_array_add (vpnc_argv, (gpointer) "--no-detach");
	g_ptr_array_add (vpnc_argv, (gpointer) "-");
	g_ptr_array_add (vpnc_argv, NULL);

	if (!g_spawn_async_with_pipes (NULL, (char **) vpnc_argv->pdata, NULL,
							 G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, &stdin_fd,
							 NULL, NULL, error)) {
		g_ptr_array_free (vpnc_argv, TRUE);
		nm_warning ("vpnc failed to start.  error: '%s'", (*error)->message);
		return -1;
	}
	g_ptr_array_free (vpnc_argv, TRUE);

	nm_info ("vpnc started with pid %d", pid);

	NM_VPNC_PLUGIN_GET_PRIVATE (plugin)->pid = pid;
	vpnc_watch = g_child_watch_source_new (pid);
	g_source_set_callback (vpnc_watch, (GSourceFunc) vpnc_watch_cb, plugin, NULL);
	g_source_attach (vpnc_watch, NULL);
	g_source_unref (vpnc_watch);

	return stdin_fd;
}

static inline void
write_config_option (int fd, const char *format, ...)
{
	char * 	string;
	va_list	args;
	int		x;

	va_start (args, format);
	string = g_strdup_vprintf (format, args);
	x = write (fd, string, strlen (string));

	if (debug)
		g_print ("Config: %s", string);

	g_free (string);
	va_end (args);
}

typedef struct {
	int fd;
	GError *error;
	gboolean upw_ignored;
	gboolean gpw_ignored;
} WriteConfigInfo;

static void
write_one_property (const char *key, const char *value, gpointer user_data)
{
	WriteConfigInfo *info = (WriteConfigInfo *) user_data;
	GType type = G_TYPE_INVALID;
	int i;

	if (info->error)
		return;

	/* Find the value in the table to get its type */
	for (i = 0; valid_properties[i].name; i++) {
		ValidProperty prop = valid_properties[i];

		if (!strcmp (prop.name, (char *) key)) {
  			/* Property is ok */
  			type = prop.type;
			break;
		}
	}

	/* Try the valid secrets table */
	for (i = 0; type == G_TYPE_INVALID && valid_secrets[i].name; i++) {
		ValidProperty prop = valid_secrets[i];

		if (!strcmp (prop.name, (char *) key)) {
  			/* Property is ok */
  			type = prop.type;
			break;
		}
	}

	if (type == G_TYPE_INVALID) {
		g_set_error (&info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Config option '%s' invalid or unknown.",
		             (const char *) key);
	}	

	/* Don't write ignored secrets */
	if (!strcmp (key, NM_VPNC_KEY_XAUTH_PASSWORD) && info->upw_ignored)
		return;
	if (!strcmp (key, NM_VPNC_KEY_SECRET) && info->gpw_ignored)
		return;

	if (type == G_TYPE_STRING)
		write_config_option (info->fd, "%s %s\n", (char *) key, (char *) value);
	else if (type == G_TYPE_BOOLEAN) {
		if (!strcmp (value, "yes"))
			write_config_option (info->fd, "%s\n", (char *) key);
	} else if (type == G_TYPE_INT) {
		long int tmp_int;
		char *tmp_str;

		/* Convert -> int and back to string for security's sake since
		 * strtol() ignores leading and trailing characters.
		 */
		errno = 0;
		tmp_int = strtol (value, NULL, 10);
		if (errno == 0) {
			tmp_str = g_strdup_printf ("%ld", tmp_int);
			write_config_option (info->fd, "%s %s\n", (char *) key, tmp_str);
			g_free (tmp_str);
		} else {
			g_set_error (&info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "Config option '%s' not an integer.",
			             (const char *) key);
		}
	} else if (type == G_TYPE_NONE) {
		/* ignored */
	} else {
		/* Just ignore unknown properties */
		nm_warning ("Don't know how to write property '%s' with type %s",
				  (char *) key, g_type_name (type));
	}
}

static gboolean
nm_vpnc_config_write (gint vpnc_fd,
                      NMSettingVPN *s_vpn,
                      GError **error)
{
	WriteConfigInfo *info;
	const char *props_username;
	const char *props_natt_mode;
	const char *default_username;
	const char *pw_type;
	const char *local_port;

	default_username = nm_setting_vpn_get_user_name (s_vpn);

	if (debug)
		write_config_option (vpnc_fd, "Debug 3\n");

	write_config_option (vpnc_fd, "Script " NM_VPNC_HELPER_PATH "\n");

	write_config_option (vpnc_fd,
	                     NM_VPNC_KEY_CISCO_UDP_ENCAPS_PORT " %d\n",
	                     NM_VPNC_UDP_ENCAPSULATION_PORT);

	local_port = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_LOCAL_PORT);
	if (!local_port) {
		/* Configure 'Local Port' to 0 (random port) if the value is not set in the setting.
		 * Otherwise vpnc would try to use 500 and could clash with other IKE processes.
		 */
		write_config_option (vpnc_fd,
		                     NM_VPNC_KEY_LOCAL_PORT " %d\n",
		                     NM_VPNC_LOCAL_PORT_ISAKMP);
	}

	/* Fill username if it's not present */
	props_username = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER);
	if (   default_username
	    && strlen (default_username)
	    && (!props_username || !strlen (props_username))) {
		write_config_option (vpnc_fd,
		                     NM_VPNC_KEY_XAUTH_USER " %s\n",
		                     default_username);
	}
	
	/* Use Cisco UDP by default */
	props_natt_mode = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	if (!props_natt_mode || !strlen (props_natt_mode)) {
		write_config_option (vpnc_fd,
		                     NM_VPNC_KEY_NAT_TRAVERSAL_MODE " %s\n",
		                     NM_VPNC_NATT_MODE_CISCO);
	} else if (props_natt_mode && (!strcmp (props_natt_mode, NM_VPNC_NATT_MODE_NATT_ALWAYS))) {
		write_config_option (vpnc_fd,
		                     NM_VPNC_KEY_NAT_TRAVERSAL_MODE " %s\n",
		                     NM_VPNC_NATT_MODE_NATT_ALWAYS);
	}

	info = g_malloc0 (sizeof (WriteConfigInfo));
	info->fd = vpnc_fd;

	/* Check for ignored user password */
	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD_TYPE);
	if (pw_type && !strcmp (pw_type, NM_VPNC_PW_TYPE_UNUSED))
		info->upw_ignored = TRUE;

	/* Check for ignored group password */
	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_SECRET_TYPE);
	if (pw_type && !strcmp (pw_type, NM_VPNC_PW_TYPE_UNUSED))
		info->gpw_ignored = TRUE;

	nm_setting_vpn_foreach_data_item (s_vpn, write_one_property, info);
	nm_setting_vpn_foreach_secret (s_vpn, write_one_property, info);
	*error = info->error;
	g_free (info);

	return *error ? FALSE : TRUE;
}

static gboolean
real_connect (NMVPNPlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	NMSettingVPN *s_vpn;
	gint vpnc_fd = -1;
	gboolean success = FALSE;

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	g_assert (s_vpn);

	if (!nm_vpnc_properties_validate (s_vpn, error))
		goto out;
	if (!nm_vpnc_secrets_validate (s_vpn, error))
		goto out;

	vpnc_fd = nm_vpnc_start_vpnc_binary (NM_VPNC_PLUGIN (plugin), error);
	if (vpnc_fd < 0)
		goto out;

	if (getenv ("NM_VPNC_DUMP_CONNECTION") || debug)
		nm_connection_dump (connection);

	if (!nm_vpnc_config_write (vpnc_fd, s_vpn, error))
		goto out;

	success = TRUE;

out:
	if (vpnc_fd >= 0)
		close (vpnc_fd);
	return success;
}

static gboolean
real_need_secrets (NMVPNPlugin *plugin,
                   NMConnection *connection,
                   char **setting_name,
                   GError **error)
{
	NMSettingVPN *s_vpn;
	const char *pw_type;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
        g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             "Could not process the request because the VPN connection settings were invalid.");
		return FALSE;
	}

	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_SECRET_TYPE);
	if (!pw_type || strcmp (pw_type, NM_VPNC_PW_TYPE_UNUSED)) {
		if (!nm_setting_vpn_get_secret (s_vpn, NM_VPNC_KEY_SECRET)) {
			*setting_name = NM_SETTING_VPN_SETTING_NAME;
			return TRUE;
		}
	}

	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD_TYPE);
	if (!pw_type || strcmp (pw_type, NM_VPNC_PW_TYPE_UNUSED)) {
		if (!nm_setting_vpn_get_secret (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD)) {
			*setting_name = NM_SETTING_VPN_SETTING_NAME;
			return TRUE;
		}
	}

	return FALSE;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	return FALSE;
}

static gboolean
real_disconnect (NMVPNPlugin   *plugin,
			  GError       **err)
{
	NMVPNCPluginPrivate *priv = NM_VPNC_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid) {
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
		else
			kill (priv->pid, SIGKILL);

		nm_info ("Terminated vpnc daemon with PID %d.", priv->pid);
		priv->pid = 0;
	}

	return TRUE;
}

static void
nm_vpnc_plugin_init (NMVPNCPlugin *plugin)
{
}

static void
nm_vpnc_plugin_class_init (NMVPNCPluginClass *vpnc_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (vpnc_class);
	NMVPNPluginClass *parent_class = NM_VPN_PLUGIN_CLASS (vpnc_class);

	g_type_class_add_private (object_class, sizeof (NMVPNCPluginPrivate));

	/* virtual methods */
	parent_class->connect    = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect = real_disconnect;
}

NMVPNCPlugin *
nm_vpnc_plugin_new (void)
{
	return (NMVPNCPlugin *) g_object_new (NM_TYPE_VPNC_PLUGIN,
								   NM_VPN_PLUGIN_DBUS_SERVICE_NAME, NM_DBUS_SERVICE_VPNC,
								   NULL);
}

static void
signal_handler (int signo)
{
	if (signo == SIGINT || signo == SIGTERM)
		g_main_loop_quit (loop);
}

static void
setup_signals (void)
{
	struct sigaction action;
	sigset_t mask;

	sigemptyset (&mask);
	action.sa_handler = signal_handler;
	action.sa_mask = mask;
	action.sa_flags = 0;
	sigaction (SIGTERM,  &action, NULL);
	sigaction (SIGINT,  &action, NULL);
}

static void
quit_mainloop (NMVPNCPlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	NMVPNCPlugin *plugin;
	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, "Don't quit when VPN connection terminates", NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &debug, "Enable verbose debug logging (may expose passwords)", NULL },
		{NULL}
	};

	g_type_init ();

	/* Parse options */
	opt_ctx = g_option_context_new ("");
	g_option_context_set_translation_domain (opt_ctx, "UTF-8");
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
		"nm-vpnc-service provides integrated Cisco Legacy IPSec VPN capability to NetworkManager.");

	g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);

	if (getenv ("VPNC_DEBUG"))
		debug = TRUE;

	if (debug)
		g_message ("nm-vpnc-service (version " DIST_VERSION ") starting...");

	if (system ("/sbin/modprobe tun") == -1)
		exit (EXIT_FAILURE);

	plugin = nm_vpnc_plugin_new ();
	if (!plugin)
		exit (EXIT_FAILURE);

	loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), loop);

	setup_signals ();
	g_main_loop_run (loop);

	g_main_loop_unref (loop);
	g_object_unref (plugin);

	exit (EXIT_SUCCESS);
}

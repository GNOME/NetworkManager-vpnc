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

#include "nm-default.h"

#include "nm-vpnc-service.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ttydefaults.h>
#include <errno.h>
#include <locale.h>

#include "utils.h"
#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

static struct {
	gboolean debug;
	int log_level;
	int log_level_native;
	GMainLoop *loop;
} gl/*obal*/;

/* TRUE if we can use vpnc's interactive mode (version 0.5.4 or greater)*/
static gboolean interactive_available = FALSE;

G_DEFINE_TYPE (NMVPNCPlugin, nm_vpnc_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

typedef struct {
	int fd;
	GIOChannel *channel;
	guint watch;
	GString *buf;
	gsize bufend;
	FILE *logf;
} Pipe;

typedef struct {
	GPid pid;
	char *pid_file;

	guint watch_id;
	gboolean interactive;

	int infd;
	Pipe out;
	Pipe err;

	GString *server_message;
	gboolean server_message_done;
	const char *pending_auth;
} NMVPNCPluginPrivate;

#define NM_VPNC_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPNC_PLUGIN, NMVPNCPluginPrivate))

#define NM_VPNC_HELPER_PATH            LIBEXECDIR"/nm-vpnc-service-vpnc-helper"
#define NM_VPNC_PID_PATH               LOCALSTATEDIR"/run/NetworkManager"
#define NM_VPNC_UDP_ENCAPSULATION_PORT 0 /* random port */
#define NM_VPNC_LOCAL_PORT_ISAKMP      0 /* random port */

typedef enum {
	ITEM_TYPE_UNKNOWN = 0,
	ITEM_TYPE_IGNORED,
	ITEM_TYPE_STRING,
	ITEM_TYPE_SECRET,
	ITEM_TYPE_BOOLEAN,
	ITEM_TYPE_INT,
	ITEM_TYPE_PATH
} ItemType;

typedef struct {
	const char *name;
	guint32 type;
	gint int_min;
	gint int_max;
} ValidProperty;

#define LEGACY_NAT_KEEPALIVE "NAT-Keepalive packet interval"

static ValidProperty valid_properties[] = {
	{ NM_VPNC_KEY_GATEWAY,               ITEM_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_ID,                    ITEM_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_XAUTH_USER,            ITEM_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_DOMAIN,                ITEM_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_DHGROUP,               ITEM_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_PERFECT_FORWARD,       ITEM_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_VENDOR,                ITEM_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_APP_VERSION,           ITEM_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_SINGLE_DES,            ITEM_TYPE_BOOLEAN, 0, 0 },
	{ NM_VPNC_KEY_NO_ENCRYPTION,         ITEM_TYPE_BOOLEAN, 0, 0 },
	{ NM_VPNC_KEY_DPD_IDLE_TIMEOUT,      ITEM_TYPE_INT, 0, 86400 },
	{ NM_VPNC_KEY_NAT_TRAVERSAL_MODE,    ITEM_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_CISCO_UDP_ENCAPS_PORT, ITEM_TYPE_INT, 0, 65535 },
	{ NM_VPNC_KEY_LOCAL_PORT,            ITEM_TYPE_INT, 0, 65535 },
	{ NM_VPNC_KEY_MTU,                   ITEM_TYPE_INT, 1200, 12000 },
	{ NM_VPNC_KEY_WEAK_AUTH,             ITEM_TYPE_BOOLEAN, 0, 0 },
	{ NM_VPNC_KEY_WEAK_ENCRYPT,          ITEM_TYPE_BOOLEAN, 0, 0 },
	/* Hybrid Auth */
	{ NM_VPNC_KEY_AUTHMODE,              ITEM_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_CA_FILE,               ITEM_TYPE_PATH, 0, 0 },
	/* Ignored option for internal use */
	{ NM_VPNC_KEY_SECRET_TYPE,           ITEM_TYPE_IGNORED, 0, 0 },
	{ NM_VPNC_KEY_XAUTH_PASSWORD_TYPE,   ITEM_TYPE_IGNORED, 0, 0 },
	{ NM_VPNC_KEY_SECRET"-flags",        ITEM_TYPE_IGNORED, 0, 0 },
	{ NM_VPNC_KEY_XAUTH_PASSWORD"-flags",ITEM_TYPE_IGNORED, 0, 0 },
	/* Legacy options that are ignored */
	{ LEGACY_NAT_KEEPALIVE,              ITEM_TYPE_STRING, 0, 0 },
	{ NULL,                              ITEM_TYPE_UNKNOWN, 0, 0 }
};

static ValidProperty valid_secrets[] = {
	{ NM_VPNC_KEY_SECRET,                ITEM_TYPE_SECRET, 0, 0 },
	{ NM_VPNC_KEY_XAUTH_PASSWORD,        ITEM_TYPE_SECRET, 0, 0 },
	{ NULL,                              ITEM_TYPE_UNKNOWN, 0, 0 }
};

/*****************************************************************************/

#define _NMLOG(level, ...) \
	G_STMT_START { \
		if (gl.log_level >= (level)) { \
			g_print ("nm-vpnc[%ld] %-7s " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
			         (long) getpid (), \
			         nm_utils_syslog_to_str (level) \
			         _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
		} \
	} G_STMT_END

static gboolean
_LOGD_enabled (void)
{
	return gl.log_level >= LOG_INFO;
}

#define _LOGD(...) _NMLOG(LOG_INFO,    __VA_ARGS__)
#define _LOGI(...) _NMLOG(LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(LOG_WARNING, __VA_ARGS__)

/*****************************************************************************/

typedef struct ValidateInfo {
	ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	ValidProperty *prop = NULL;
	long int tmp;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		prop = &info->table[i];
		if (g_strcmp0 (prop->name, key) == 0)
			break;
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!prop || !prop->name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("property “%s” invalid or not supported"),
		             key);
		return;
	}

	/* Validate the property */
	switch (prop->type) {
	case ITEM_TYPE_IGNORED:
		break; /* technically valid, but unused */
	case ITEM_TYPE_STRING:
	case ITEM_TYPE_SECRET:
		if (strchr (value, '\n') || strchr (value, '\r')) {
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("property “%s” contains a newline character"),
			             key);
		}
		break;
	case ITEM_TYPE_PATH:
		if (   !value
		    || !strlen (value)
		    || !g_path_is_absolute (value)
		    || !g_file_test (value, G_FILE_TEST_EXISTS)) {
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("property “%s” file path “%s” is not absolute or does not exist"),
			             key, value);
		}
		break;
	case ITEM_TYPE_INT:
		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno == 0 && tmp >= prop->int_min && tmp <= prop->int_max)
			break; /* valid */

		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("invalid integer property “%s” or out of range [%d -> %d]"),
		             key, prop->int_min, prop->int_max);
		break;
	case ITEM_TYPE_BOOLEAN:
		if (!strcmp (value, "yes") || !strcmp (value, "no"))
			break; /* valid */

		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("invalid boolean property “%s” (not yes or no)"),
		             key);
		break;
	default:
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("unhandled property “%s” type %d"),
		             key, prop->type);
		break;
	}
}

static gboolean
nm_vpnc_properties_validate (NMSettingVpn *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_properties[0], error, FALSE };

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN configuration options."));
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

static gboolean
nm_vpnc_secrets_validate (NMSettingVpn *s_vpn,
                          gboolean allow_missing,
                          GError **error)
{
	GError *validate_error = NULL;
	ValidateInfo info = { &valid_secrets[0], &validate_error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (validate_error) {
		g_propagate_error (error, validate_error);
		return FALSE;
	}

	if (allow_missing == FALSE && !info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN secrets!"));
		return FALSE;
	}

	return TRUE;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);
	waitpid (pid, NULL, 0);

	return FALSE;
}

static void
pipe_cleanup (Pipe *pipe)
{
	if (pipe->channel) {
		g_source_remove (pipe->watch);
		pipe->watch = 0;
		g_io_channel_shutdown (pipe->channel, FALSE, NULL);
		g_io_channel_unref (pipe->channel);
		pipe->channel = NULL;
	}
	if (pipe->fd >= 0) {
		close (pipe->fd);
		pipe->fd = -1;
	}
	if (pipe->buf) {
		g_string_free (pipe->buf, TRUE);
		pipe->buf = NULL;
	}
}

static void
pipe_echo_finish (Pipe *pipe)
{
	GIOStatus status;
	gsize bytes_read;
	char buf[512];

	do {
		bytes_read = 0;
		status = g_io_channel_read_chars (pipe->channel,
		                                  buf,
		                                  sizeof (buf),
		                                  &bytes_read,
		                                  NULL);
		if (bytes_read) {
			fprintf (pipe->logf, "%.*s", (int) bytes_read, buf);
			fflush (pipe->logf);
		}
	} while (status == G_IO_STATUS_NORMAL);
}

static void
vpnc_cleanup (NMVPNCPlugin *self, gboolean killit)
{
	NMVPNCPluginPrivate *priv = NM_VPNC_PLUGIN_GET_PRIVATE (self);

	if (priv->infd >= 0) {
		close (priv->infd);
		priv->infd = -1;
	}

	pipe_cleanup (&priv->out);
	pipe_cleanup (&priv->err);
	g_string_truncate (priv->server_message, 0);
	priv->server_message_done = FALSE;

	if (priv->watch_id) {
		g_source_remove (priv->watch_id);
		priv->watch_id = 0;
	}

	if (priv->pid) {
		if (killit) {
			/* Try giving it some time to disconnect cleanly */
			if (kill (priv->pid, SIGTERM) == 0)
				g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
			_LOGI ("Terminated vpnc daemon with PID %d.", priv->pid);
		} else {
			/* Already quit, just reap the child */
			waitpid (priv->pid, NULL, WNOHANG);
		}
		priv->pid = 0;
	}
}

static void
remove_pidfile (NMVPNCPlugin *plugin)
{
	NMVPNCPluginPrivate *priv = NM_VPNC_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid_file) {
		unlink (priv->pid_file);
		g_free (priv->pid_file);
		priv->pid_file = NULL;
	}
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
			_LOGW ("vpnc exited with error code %d", error);
	} else if (WIFSTOPPED (status))
		_LOGW ("vpnc stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		_LOGW ("vpnc died with signal %d", WTERMSIG (status));
	else
		_LOGW ("vpnc died from an unknown cause");

	priv->watch_id = 0;

	/* Grab any remaining output, if any */
	if (priv->out.channel)
		pipe_echo_finish (&priv->out);
	if (priv->err.channel)
		pipe_echo_finish (&priv->err);

	vpnc_cleanup (plugin, FALSE);
	remove_pidfile (plugin);

	/* Must be after data->state is set since signals use data->state */
	switch (error) {
	case 2:
		/* Couldn't log in due to bad user/pass */
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
		break;
	case 1:
		/* Other error (couldn't bind to address, etc) */
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (plugin), NULL);
		break;
	}
}

#define XAUTH_USERNAME_PROMPT "Enter username for "
#define XAUTH_PASSWORD_PROMPT "Enter password for "
#define IPSEC_SECRET_PROMPT   "Enter IPSec secret for "
#define ASYNC_ANSWER_PROMPT   "Answer for VPN "
#define ASYNC_PASSCODE_PROMPT "Passcode for VPN "
#define ASYNC_PASSWORD_PROMPT "Password for VPN "

typedef struct {
	const char *prompt;
	const char *hint;
} PromptHintMap;

static const PromptHintMap phmap[] = {
	/* Username */
	{ XAUTH_USERNAME_PROMPT, NM_VPNC_KEY_XAUTH_USER },

	/* User password */
	{ XAUTH_PASSWORD_PROMPT, NM_VPNC_KEY_XAUTH_PASSWORD },
	{ ASYNC_PASSWORD_PROMPT, NM_VPNC_KEY_XAUTH_PASSWORD },

	/* Group password */
	{ IPSEC_SECRET_PROMPT,   NM_VPNC_KEY_SECRET },

	/* FIXME: add new secret item for these? */
	{ ASYNC_ANSWER_PROMPT,   NM_VPNC_KEY_XAUTH_PASSWORD },
	{ ASYNC_PASSCODE_PROMPT, NM_VPNC_KEY_XAUTH_PASSWORD },
};

static void
vpnc_prompt (const char *data, gsize dlen, gpointer user_data)
{
	NMVPNCPlugin *plugin = NM_VPNC_PLUGIN (user_data);
	NMVPNCPluginPrivate *priv = NM_VPNC_PLUGIN_GET_PRIVATE (plugin);
	const char *hints[2] = { NULL, NULL };
	char *prompt;
	guint i;

	g_warn_if_fail (priv->pending_auth == NULL);
	priv->pending_auth = NULL;

	prompt = g_strndup (data, dlen);
	_LOGD ("vpnc requested input: '%s'", prompt);
	for (i = 0; i < G_N_ELEMENTS (phmap); i++) {
		if (g_str_has_prefix (prompt, phmap[i].prompt)) {
			hints[0] = phmap[i].hint;
			break;
		}
	}

	if (!hints[0]) {
		_LOGD ("Unhandled vpnc message '%s'", prompt);
		g_free (prompt);
		return;
	}

	_LOGD ("Requesting new secrets: '%s' (%s)", prompt, hints[0]);

	nm_vpn_service_plugin_secrets_required (NM_VPN_SERVICE_PLUGIN (plugin),
	                                priv->server_message->len ? priv->server_message->str : prompt,
	                                (const char **) hints);
	g_string_truncate (priv->server_message, 0);
	g_free (prompt);

	priv->pending_auth = hints[0];
}

static gboolean
data_available (GIOChannel *source,
                GIOCondition condition,
                gpointer data)
{
	NMVPNCPlugin *plugin = NM_VPNC_PLUGIN (data);
	NMVPNCPluginPrivate *priv = NM_VPNC_PLUGIN_GET_PRIVATE (plugin);
	GError *error = NULL;
	Pipe *pipe = NULL;
	gsize bytes_read = 0;
	GIOStatus status;

	/* Figure out which pipe we're using */
	if (source == priv->out.channel)
		pipe = &priv->out;
	else if (source == priv->err.channel)
		pipe = &priv->err;
	else
		g_assert_not_reached ();

	if (condition & G_IO_ERR) {
		_LOGW ("Unexpected vpnc pipe error");
		goto fail;
	}

	do {
		gsize consumed = 0;
		char buf[512];

		status = g_io_channel_read_chars (source,
		                                  buf,
		                                  sizeof (buf),
		                                  &bytes_read,
		                                  &error);
		if (status == G_IO_STATUS_ERROR) {
			if (error)
				_LOGW ("vpnc read error: %s", error->message);
			g_clear_error (&error);
		}

		if (bytes_read) {
			g_string_append_len (pipe->buf, buf, bytes_read);

			do {
				consumed = utils_handle_output (pipe->buf,
				                                priv->server_message,
				                                &priv->server_message_done,
				                                vpnc_prompt,
				                                plugin);
				if (consumed) {
					/* Log all output to the console */
					fprintf (pipe->logf, "%.*s", (int) consumed, pipe->buf->str);
					fflush (pipe->logf);

					/* If output was handled, clear the buffer */
					g_string_erase (pipe->buf, 0, consumed);
				}
			} while (consumed);
		}

		if (status == G_IO_STATUS_EOF)
			goto fail;
	} while (bytes_read);

	return TRUE;

fail:
	pipe->watch = 0;
	return FALSE;
}

static void
pipe_setup (Pipe *pipe, FILE *logf, gpointer user_data)
{
	GIOFlags flags = 0;

	pipe->logf = logf;
	pipe->buf = g_string_sized_new (512);

	pipe->channel = g_io_channel_unix_new (pipe->fd);
	g_io_channel_set_encoding (pipe->channel, NULL, NULL);
	flags = g_io_channel_get_flags (pipe->channel);
	g_io_channel_set_flags (pipe->channel, flags | G_IO_FLAG_NONBLOCK, NULL);
	g_io_channel_set_buffered (pipe->channel, FALSE);

	pipe->watch = g_io_add_watch (pipe->channel,
	                              G_IO_IN | G_IO_ERR | G_IO_PRI,
	                              data_available,
	                              user_data);
}

static const char *
find_vpnc (void)
{
	static const char *vpnc_paths[] = {
		"/usr/sbin/vpnc",
		"/sbin/vpnc",
		"/usr/local/sbin/vpnc",
		NULL
	};
	guint i;

	/* Find vpnc */
	for (i = 0; vpnc_paths[i]; i++) {
		if (g_file_test (vpnc_paths[i], G_FILE_TEST_EXISTS))
			return vpnc_paths[i];
	}
	return NULL;
}

static gboolean
nm_vpnc_start_vpnc_binary (NMVPNCPlugin *plugin, gboolean interactive, GError **error)
{
	NMVPNCPluginPrivate *priv = NM_VPNC_PLUGIN_GET_PRIVATE (plugin);
	const char *vpnc_path;
	const char *args[10];
	guint i = 0;

	g_return_val_if_fail (priv->pid == 0, FALSE);
	g_return_val_if_fail (priv->infd == -1, FALSE);
	g_return_val_if_fail (priv->out.fd == -1, FALSE);
	g_return_val_if_fail (priv->err.fd == -1, FALSE);

	vpnc_path = find_vpnc ();
	if (!vpnc_path) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		                     _("Could not find vpnc binary."));
		return FALSE;
	}

	args[i++] = vpnc_path;
	args[i++] = "--no-detach";
	args[i++] = "--pid-file";
	args[i++] = priv->pid_file;
	if (!interactive)
		args[i++] = "--non-inter";
	args[i++] = "-";
	args[i++] = NULL;
	if (!g_spawn_async_with_pipes (NULL,
	                               (char **) args,
	                               NULL,
	                               G_SPAWN_DO_NOT_REAP_CHILD,
	                               NULL,
	                               NULL,
	                               &priv->pid,
	                               &priv->infd,
	                               interactive ? &priv->out.fd : NULL,
	                               interactive ? &priv->err.fd : NULL,
	                               error)) {
		_LOGW ("vpnc failed to start.  error: '%s'", (*error)->message);
		return FALSE;
	}
	_LOGI ("vpnc started with pid %d", priv->pid);

	priv->watch_id = g_child_watch_add (priv->pid, vpnc_watch_cb, plugin);

	if (interactive) {
		/* Watch stdout and stderr */
		pipe_setup (&priv->out, stdout, plugin);
		pipe_setup (&priv->err, stderr, plugin);
	}
	return TRUE;
}

__attribute__((__format__ (__printf__, 2, 3)))
static void
write_config_option (int fd, const char *format, ...)
{
	gs_free char *string = NULL;
	va_list args;
	int x;

	va_start (args, format);
	string = g_strdup_vprintf (format, args);
	va_end (args);

	x = write (fd, string, strlen (string));
	if (x < 0)
		_LOGW ("Unexpected error in write(): %d", errno);
	x = write (fd, "\n", 1);
	if (x < 0)
		_LOGW ("Unexpected error in write(): %d", errno);

	_LOGD ("Config: %s", string);
}

static void
write_config_option_secret (int fd, const char *key, const char *value)
{
	gs_free char *string = NULL;
	int x;

	string = g_strdup_printf ("%s %s\n", key, value);

	x = write (fd, string, strlen (string));
	if (x < 0)
		_LOGW ("Unexpected error in write(): %d", errno);

	_LOGD ("Config: %s <hidden>", key);
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
	guint32 type = ITEM_TYPE_UNKNOWN;
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
	for (i = 0; type == ITEM_TYPE_UNKNOWN && valid_secrets[i].name; i++) {
		ValidProperty prop = valid_secrets[i];

		if (!strcmp (prop.name, (char *) key)) {
			/* Property is ok */
			type = prop.type;
			break;
		}
	}

	if (type == ITEM_TYPE_UNKNOWN) {
		g_set_error (&info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("Config option “%s” invalid or unknown."),
		             (const char *) key);
		return;
	}

	/* Don't write ignored secrets */
	if (!strcmp (key, NM_VPNC_KEY_XAUTH_PASSWORD) && info->upw_ignored)
		return;
	if (!strcmp (key, NM_VPNC_KEY_SECRET) && info->gpw_ignored)
		return;

	if (type == ITEM_TYPE_STRING || type == ITEM_TYPE_PATH)
		write_config_option (info->fd, "%s %s", (char *) key, (char *) value);
	else if (type == ITEM_TYPE_SECRET)
		write_config_option_secret (info->fd, key, value);
	else if (type == ITEM_TYPE_BOOLEAN) {
		if (!strcmp (value, "yes"))
			write_config_option (info->fd, "%s", (char *) key);
	} else if (type == ITEM_TYPE_INT) {
		long int tmp_int;
		char *tmp_str;

		/* Convert -> int and back to string for security's sake since
		 * strtol() ignores leading and trailing characters.
		 */
		errno = 0;
		tmp_int = strtol (value, NULL, 10);
		if (errno == 0) {
			tmp_str = g_strdup_printf ("%ld", tmp_int);
			write_config_option (info->fd, "%s %s", (char *) key, tmp_str);
			g_free (tmp_str);
		} else {
			g_set_error (&info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Config option “%s” not an integer."),
			             (const char *) key);
		}
	} else if (type == ITEM_TYPE_IGNORED) {
		/* ignored */
	} else {
		/* Just ignore unknown properties */
		_LOGW ("Don't know how to write property '%s' with type %d", key, type);
	}
}

static gboolean
nm_vpnc_config_write (gint vpnc_fd,
                      const char *bus_name,
                      NMSettingConnection *s_con,
                      NMSettingVpn *s_vpn,
                      GError **error)
{
	WriteConfigInfo *info;
	const char *props_username;
	const char *props_natt_mode;
	const char *default_username;
	const char *pw_type;
	const char *local_port;
	const char *interface_name;
	NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

	if (bus_name) {
		g_assert (g_dbus_is_name (bus_name));
		if (nm_streq (bus_name, NM_DBUS_SERVICE_VPNC))
			bus_name = NULL;
	}

	interface_name = nm_setting_connection_get_interface_name(s_con);

	default_username = nm_setting_vpn_get_user_name (s_vpn);

	write_config_option (vpnc_fd, "Debug %d", gl.log_level_native);

	if (interface_name && strlen(interface_name) > 0)
		write_config_option (vpnc_fd, "Interface name %s", interface_name);

	write_config_option (vpnc_fd, "Script %s %d %ld %s%s",
	                     NM_VPNC_HELPER_PATH,
	                     gl.log_level,
	                     (long) getpid(),
	                     bus_name ? " --bus-name " : "", bus_name ?: "");

	write_config_option (vpnc_fd,
	                     NM_VPNC_KEY_CISCO_UDP_ENCAPS_PORT " %d",
	                     NM_VPNC_UDP_ENCAPSULATION_PORT);

	local_port = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_LOCAL_PORT);
	if (!local_port) {
		/* Configure 'Local Port' to 0 (random port) if the value is not set in the setting.
		 * Otherwise vpnc would try to use 500 and could clash with other IKE processes.
		 */
		write_config_option (vpnc_fd,
		                     NM_VPNC_KEY_LOCAL_PORT " %d",
		                     NM_VPNC_LOCAL_PORT_ISAKMP);
	}

	/* Fill username if it's not present */
	props_username = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER);
	if (   default_username
	    && strlen (default_username)
	    && (!props_username || !strlen (props_username))) {
		write_config_option (vpnc_fd,
		                     NM_VPNC_KEY_XAUTH_USER " %s",
		                     default_username);
	}

	/* Use Cisco UDP by default */
	props_natt_mode = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	if (!props_natt_mode || !strlen (props_natt_mode)) {
		write_config_option (vpnc_fd,
		                     NM_VPNC_KEY_NAT_TRAVERSAL_MODE " %s",
		                     NM_VPNC_NATT_MODE_CISCO);
	} else if (props_natt_mode && (!strcmp (props_natt_mode, NM_VPNC_NATT_MODE_NATT_ALWAYS))) {
		write_config_option (vpnc_fd,
		                     NM_VPNC_KEY_NAT_TRAVERSAL_MODE " %s",
		                     NM_VPNC_NATT_MODE_NATT_ALWAYS);
	}

	info = g_malloc0 (sizeof (WriteConfigInfo));
	info->fd = vpnc_fd;

	/* Check for ignored user password */
	if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_VPNC_KEY_XAUTH_PASSWORD, &secret_flags, NULL)) {
		if (secret_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
			info->upw_ignored = TRUE;
	} else {
		pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD_TYPE);
		if (pw_type && !strcmp (pw_type, NM_VPNC_PW_TYPE_UNUSED))
			info->upw_ignored = TRUE;
	}

	/* Check for ignored group password */
	secret_flags = NM_SETTING_SECRET_FLAG_NONE;
	if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_VPNC_KEY_SECRET, &secret_flags, NULL)) {
		if (secret_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
			info->gpw_ignored = TRUE;
	} else {
		pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_SECRET_TYPE);
		if (pw_type && !strcmp (pw_type, NM_VPNC_PW_TYPE_UNUSED))
			info->gpw_ignored = TRUE;
	}

	nm_setting_vpn_foreach_data_item (s_vpn, write_one_property, info);
	nm_setting_vpn_foreach_secret (s_vpn, write_one_property, info);
	*error = info->error;
	g_free (info);

	return *error ? FALSE : TRUE;
}

static gboolean
_connect_common (NMVpnServicePlugin   *plugin,
                 gboolean       interactive,
                 NMConnection  *connection,
                 GVariant      *details,
                 GError       **error)
{
	NMVPNCPluginPrivate *priv = NM_VPNC_PLUGIN_GET_PRIVATE (plugin);
	NMSettingVpn *s_vpn;
	NMSettingConnection *s_con;
	char end[] = { 0x04 };
	gs_free char *bus_name = NULL;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	if (!nm_vpnc_properties_validate (s_vpn, error))
		goto out;

	if (!nm_vpnc_secrets_validate (s_vpn, interactive, error))
		goto out;

	priv->pid_file = g_strdup_printf (NM_VPNC_PID_PATH "/nm-vpnc-%s.pid", nm_connection_get_uuid (connection));

	if (!nm_vpnc_start_vpnc_binary (NM_VPNC_PLUGIN (plugin), interactive, error))
		goto out;

	if (_LOGD_enabled () || getenv ("NM_VPNC_DUMP_CONNECTION")) {
		_LOGD ("connection:");
		nm_connection_dump (connection);
	}

	g_object_get (plugin, NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, &bus_name, NULL);
	if (!nm_vpnc_config_write (priv->infd, bus_name, s_con, s_vpn, error))
		goto out;

	if (interactive) {
		if (write (priv->infd, &end, sizeof (end)) < 0)
			_LOGW ("Unexpected error in write(): %d", errno);
	} else {
		close (priv->infd);
		priv->infd = -1;
	}

	return TRUE;

out:
	vpnc_cleanup (NM_VPNC_PLUGIN (plugin), TRUE);
	return FALSE;
}

static gboolean
real_connect (NMVpnServicePlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	return _connect_common (plugin, FALSE, connection, NULL, error);
}

static gboolean
real_connect_interactive (NMVpnServicePlugin   *plugin,
                          NMConnection  *connection,
                          GVariant      *details,
                          GError       **error)
{
	if (!interactive_available) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INTERACTIVE_NOT_SUPPORTED,
		                     _("vpnc does not support interactive requests"));
		return FALSE;
	}

	if (!_connect_common (plugin, TRUE, connection, details, error))
		return FALSE;

	NM_VPNC_PLUGIN_GET_PRIVATE (plugin)->interactive = TRUE;
	return TRUE;
}

static gboolean
real_new_secrets (NMVpnServicePlugin *plugin,
                  NMConnection *connection,
                  GError **error)
{
	NMVPNCPluginPrivate *priv = NM_VPNC_PLUGIN_GET_PRIVATE (plugin);
	NMSettingVpn *s_vpn;
	const char *secret;

	if (!interactive_available || !priv->interactive) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_FAILED,
		                     _("Could not use new secrets as interactive mode is disabled."));
		return FALSE;
	}

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	if (!priv->pending_auth) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Could not process the request because no pending authentication is required."));
		return FALSE;
	}

	_LOGD ("VPN received new secrets; sending to '%s' vpnc stdin", priv->pending_auth);

	secret = nm_setting_vpn_get_secret (s_vpn, priv->pending_auth);
	if (!secret) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		             _("Could not process the request because the requested info “%s” was not provided."),
		             priv->pending_auth);
		return FALSE;
	}

	/* Ignoring secret flags here; if vpnc requested the item, we must provide it */
	write_config_option (priv->infd, "%s", secret);

	priv->pending_auth = NULL;
	return TRUE;
}

static NMSettingSecretFlags
get_pw_flags (NMSettingVpn *s_vpn, const char *secret_name, const char *type_name)
{
	const char *val;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	/* Try new flags value first */
	if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), secret_name, &flags, NULL))
		return flags;

	/* Otherwise try old "password type" value */
	val = nm_setting_vpn_get_data_item (s_vpn, type_name);
	if (val) {
		if (g_strcmp0 (val, NM_VPNC_PW_TYPE_ASK) == 0)
			return NM_SETTING_SECRET_FLAG_NOT_SAVED;
		else if (g_strcmp0 (val, NM_VPNC_PW_TYPE_UNUSED) == 0)
			return NM_SETTING_SECRET_FLAG_NOT_REQUIRED;

		/* NM_VPNC_PW_TYPE_SAVE means FLAG_NONE */
	}

	return NM_SETTING_SECRET_FLAG_NONE;
}

static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **out_setting_name,
                   GError **error)
{
	NMSettingVpn *s_vpn;
	NMSettingSecretFlags pw_flags;
	const char *pw = NULL;

	g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		             "%s",
		             _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	/* User password */
	pw = nm_setting_vpn_get_secret (s_vpn, NM_VPNC_KEY_SECRET);
	pw_flags = get_pw_flags (s_vpn, NM_VPNC_KEY_SECRET, NM_VPNC_KEY_SECRET_TYPE);
	if (!pw && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
		*out_setting_name = NM_SETTING_VPN_SETTING_NAME;
		return TRUE;
	}

	/* Group password */
	pw = nm_setting_vpn_get_secret (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD);
	pw_flags = get_pw_flags (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD, NM_VPNC_KEY_XAUTH_PASSWORD_TYPE);
	if (!pw && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
		*out_setting_name = NM_SETTING_VPN_SETTING_NAME;
		return TRUE;
	}

	return FALSE;
}

static gboolean
real_disconnect (NMVpnServicePlugin *plugin, GError **error)
{
	vpnc_cleanup (NM_VPNC_PLUGIN (plugin), TRUE);
	return TRUE;
}

static void
nm_vpnc_plugin_init (NMVPNCPlugin *plugin)
{
	NMVPNCPluginPrivate *priv = NM_VPNC_PLUGIN_GET_PRIVATE (plugin);

	priv->infd = -1;
	priv->out.fd = -1;
	priv->err.fd = -1;
	priv->server_message = g_string_sized_new (30);
}

static void
nm_vpnc_plugin_class_init (NMVPNCPluginClass *vpnc_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (vpnc_class);
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (vpnc_class);

	g_type_class_add_private (object_class, sizeof (NMVPNCPluginPrivate));

	/* virtual methods */
	parent_class->connect = real_connect;
	parent_class->connect_interactive = real_connect_interactive;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect = real_disconnect;
	parent_class->new_secrets = real_new_secrets;
}

NMVPNCPlugin *
nm_vpnc_plugin_new (const char *bus_name)
{
	NMVPNCPlugin *plugin;
	GError *error = NULL;

	plugin = (NMVPNCPlugin *) g_initable_new (NM_TYPE_VPNC_PLUGIN, NULL, &error,
	                                          NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, bus_name,
	                                          NM_VPN_SERVICE_PLUGIN_DBUS_WATCH_PEER, !gl.debug,
	                                          NULL);
	if (!plugin) {
		_LOGW ("Failed to initialize a plugin instance: %s", error->message);
		g_error_free (error);
	}

	return plugin;
}

static void
signal_handler (int signo)
{
	if (signo == SIGINT || signo == SIGTERM)
		g_main_loop_quit (gl.loop);
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

static gboolean
vpnc_check_interactive (void)
{
	const char *vpnc_path;
	const char *argv[3];
	GError *error = NULL;
	char *output = NULL;
	gboolean has_interactive = FALSE;

	vpnc_path = find_vpnc ();
	if (!vpnc_path) {
		_LOGW ("Failed to find vpnc for version check");
		return FALSE;
	}

	argv[0] = vpnc_path;
	argv[1] = "--long-help";
	argv[2] = NULL;
	if (g_spawn_sync ("/", (char **) argv, NULL, G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL, &output, NULL, NULL, &error)) {
		if (strstr (output, "--password-helper"))
			has_interactive = TRUE;
		g_free (output);
	} else {
		_LOGW ("Failed to start vpnc for version check: %s", error->message);
		g_error_free (error);
	}

	return has_interactive;
}

int
main (int argc, char *argv[])
{
	NMVPNCPlugin *plugin;
	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;
	gs_free char *bus_name_free = NULL;
	const char *bus_name;
	GError *error = NULL;

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don’t quit when VPN connection terminates"), NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &gl.debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
		{ "bus-name", 0, 0, G_OPTION_ARG_STRING, &bus_name_free, N_("D-Bus name to use for this instance"), NULL },
		{NULL}
	};

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	/* locale will be set according to environment LC_* variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NM_VPNC_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
	                              _("nm-vpnc-service provides integrated "
	                                "Cisco Legacy IPsec VPN capability to NetworkManager."));

	if (!g_option_context_parse (opt_ctx, &argc, &argv, &error)) {
		g_printerr ("Error parsing the command line options: %s\n", error->message);
		g_option_context_free (opt_ctx);
		g_clear_error (&error);
		exit (EXIT_FAILURE);
	}

	g_option_context_free (opt_ctx);

	bus_name = bus_name_free ?: NM_DBUS_SERVICE_VPNC;
	if (!g_dbus_is_name (bus_name)) {
		g_printerr ("invalid --bus-name\n");
		exit (EXIT_FAILURE);
	}

	interactive_available = vpnc_check_interactive ();

	if (getenv ("VPNC_DEBUG"))
		gl.debug = TRUE;

	gl.log_level = _nm_utils_ascii_str_to_int64 (getenv ("NM_VPN_LOG_LEVEL"),
	                                             10, 0, LOG_DEBUG, -1);

	if (gl.log_level < 0)
		gl.log_level_native = gl.debug ? 3 : 0;
	else if (gl.log_level <= 0)
		gl.log_level_native = 0;
	else if (gl.log_level <= LOG_WARNING)
		gl.log_level_native = 1;
	else if (gl.log_level <= LOG_NOTICE)
		gl.log_level_native = 2;
	else if (gl.log_level <= LOG_INFO)
		gl.log_level_native = 3;
	else {
		/* level 99 prints passwords. We don't want that even for the highest
		 * level. So, choose one below. */
		gl.log_level_native = 98;
	}

	if (gl.log_level < 0)
		gl.log_level = gl.debug ? LOG_DEBUG : LOG_NOTICE;

	_LOGD ("nm-vpnc-service (version " DIST_VERSION ") starting...");
	_LOGD ("   vpnc interactive mode is %s", interactive_available ? "enabled" : "disabled");
	_LOGD ("   uses%s --bus-name \"%s\"", bus_name_free ? "" : " default", bus_name);

	if (system ("/sbin/modprobe tun") == -1)
		exit (EXIT_FAILURE);

	plugin = nm_vpnc_plugin_new (bus_name);
	if (!plugin)
		exit (EXIT_FAILURE);

	_LOGD ("nm-vpnc-service (version " DIST_VERSION ") started.");

	gl.loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), gl.loop);

	setup_signals ();
	g_main_loop_run (gl.loop);

	remove_pidfile (plugin);

	g_main_loop_unref (gl.loop);
	gl.loop = NULL;
	g_object_unref (plugin);

	exit (EXIT_SUCCESS);
}

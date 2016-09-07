/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-vpnc-helper.c : Helper functions for nm-vpnc.c
 *
 * Copyright (C) 2011 IBM Corp. All Rights Reserved
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

#include "nm-vpnc-helper.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

gboolean
key_file_get_boolean_helper (GKeyFile *keyfile,
                             const gchar *group_name,
                             const gchar *key,
                             GError **error)
{
	gboolean bool_value = FALSE;
	gchar *new_key;

	g_return_val_if_fail (keyfile != NULL, FALSE);
	g_return_val_if_fail (group_name != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);

	new_key = g_strdup_printf ("!%s", key);

	if (g_key_file_has_key (keyfile, group_name, key, NULL))
		bool_value = g_key_file_get_boolean (keyfile, group_name, key, error);
	else if (g_key_file_has_key (keyfile, group_name, new_key, NULL))
		bool_value = g_key_file_get_boolean (keyfile, group_name, new_key, error);

	g_free (new_key);
	return bool_value;
}

gboolean
key_file_get_integer_helper (GKeyFile *keyfile,
                             const gchar *group_name,
                             const gchar *key,
                             gint *value)
{
	gchar *new_key = NULL;
	gboolean success = FALSE;
	GError *error = NULL;

	g_return_val_if_fail (keyfile != NULL, FALSE);
	g_return_val_if_fail (group_name != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	*value = 0;
	if (!key_file_has_key_helper (keyfile, group_name, key))
		return FALSE;

	new_key = g_strdup_printf ("!%s", key);

	if (g_key_file_has_key (keyfile, group_name, key, NULL))
		*value = g_key_file_get_integer (keyfile, group_name, key, &error);
	else if (g_key_file_has_key (keyfile, group_name, new_key, NULL))
		*value = g_key_file_get_integer (keyfile, group_name, new_key, &error);

	g_free (new_key);

	success = (error == NULL);
	g_clear_error (&error);
	return success;
}

static gchar *
get_string_as_utf8 (GKeyFile *keyfile,
                    const char *group_name,
                    const char *key,
                    GError **error)
{
	char *raw, *buf = NULL;

	raw = g_key_file_get_value (keyfile, group_name, key, error);
	if (raw && raw[0]) {
		if (g_utf8_validate (raw, -1, NULL))
			buf = g_key_file_get_string (keyfile, group_name, key, error);
		else {
			/* Attempt to force to UTF8 using current locale, which is about
			 * as good as we can do since the file doesn't say what locale
			 * it's in.
			 */
			buf = g_locale_to_utf8 (raw, -1, NULL, NULL, error);
		}
	}
	g_free (raw);
	return buf;
}

gchar *
key_file_get_string_helper (GKeyFile *keyfile,
                            const gchar *group_name,
                            const gchar *key,
                            GError **error)
{
	gchar *buf = NULL;
	gchar *new_key;

	g_return_val_if_fail (keyfile != NULL, NULL);
	g_return_val_if_fail (group_name != NULL, NULL);
	g_return_val_if_fail (key != NULL, NULL);

	new_key = g_strdup_printf ("!%s", key);

	if (g_key_file_has_key (keyfile, group_name, key, NULL))
		buf = get_string_as_utf8 (keyfile, group_name, key, error);
	else if (g_key_file_has_key (keyfile, group_name, new_key, NULL))
		buf = get_string_as_utf8 (keyfile, group_name, new_key, error);

	g_free (new_key);
	return buf;
}

gboolean
key_file_has_key_helper (GKeyFile *keyfile,
                         const gchar *group_name,
                         const gchar *key)
{
	gboolean bool_value = FALSE;
	gchar *new_key;

	g_return_val_if_fail (keyfile != NULL, FALSE);
	g_return_val_if_fail (group_name != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);

	new_key = g_strdup_printf ("!%s", key);

	if (g_key_file_has_key (keyfile, group_name, key, NULL)
	 || g_key_file_has_key (keyfile, group_name, new_key, NULL)) {
		bool_value = TRUE;
	}

	g_free (new_key);
	return bool_value;
}

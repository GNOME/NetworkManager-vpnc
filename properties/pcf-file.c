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
 * (C) Copyright 2005 - 2008 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>

#include "pcf-file.h"

static void
pcf_entry_free (PcfEntry *entry)
{
	if (entry) {
		g_free (entry->key);
		g_free (entry->value);
		g_free (entry);
	}
}

/*
  The main reader loop here is based on the simple .ini file
  parser from avahi/avahi-daemon/ini-file-parser.c
*/

GHashTable *
pcf_file_load (const char *fname)
{
	FILE *fo;
	unsigned line;
    GHashTable *pcf;
	GHashTable *group = NULL;
    
    g_return_val_if_fail (fname != NULL, NULL);

    if (!(fo = fopen (fname, "r"))) {
        g_warning ("Failed to open file '%s': %s", fname, strerror (errno));
        return NULL;
    }

	pcf = g_hash_table_new_full (g_str_hash, g_str_equal,
								 g_free,
								 (GDestroyNotify) g_hash_table_destroy);

    line = 0;
    while (!feof (fo)) {
        char ln[1024]; /* 4x what we think to allow for possible UTF-8 conversion */
        char *s, *e;
        
        if (!(fgets (ln, sizeof (ln) / 4, fo)))
            break;

        line++;

		if (!g_utf8_validate (ln, -1, NULL)) {
			char *tmp;
			GError *error = NULL;

			tmp = g_locale_to_utf8 (ln, -1, NULL, NULL, &error);
			if (error) {
				/* ignore the error; leave 'ln' alone.  We tried. */
				g_error_free (error);
			} else {
				g_assert (tmp);
				strcpy (ln, tmp);  /* update ln with the UTF-8 safe text */
			}
			g_free (tmp);
		}

        s = ln + strspn (ln, " \t");
        s[strcspn (s, "\r\n")] = 0;

        /* Skip comments and empty lines */
        if (*s == ';' || *s == 0)
            continue;

        if (*s == '[') {
            /* new group */
            
            if (!(e = strchr (s, ']'))) {
                g_warning ("Unclosed group header in %s:%u: <%s>", fname, line, s);
                goto fail;
            }

            *e = 0;

			group = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
										   (GDestroyNotify) pcf_entry_free);

			g_hash_table_insert (pcf, g_utf8_strdown (s+1, -1), group);
        } else {
			PcfEntry *entry;
			char *key;

            /* Normal assignment */
            if (!(e = strchr (s, '='))) {
                g_warning ("Missing assignment in %s:%u: <%s>", fname, line, s);
                goto fail;
            }
            
            if (!group) {
                g_warning ("Assignment outside group in %s:%u <%s>", fname, line, s);
                goto fail;
            }
            
            /* Split the key and the value */
            *(e++) = 0;

			entry = g_new (PcfEntry, 1);
			entry->value = g_strdup (g_strstrip (e));

			if (*s == '!') {
				key = g_utf8_strdown (s+1, -1);
				entry->read_only = TRUE;
			} else {
				key = g_utf8_strdown (s, -1);
				entry->read_only = FALSE;
			}

			entry->key = g_strdup (g_strstrip (key));
			g_free (key);
			g_hash_table_insert (group, entry->key, entry);
        }
    }

    /* Contains a main section? */
    if (!g_hash_table_lookup (pcf, "main"))
        goto fail;
    
    fclose (fo);
        
    return pcf;

fail:

    if (fo)
        fclose (fo);

    if (pcf)
        g_hash_table_destroy (pcf);

    return NULL;
}

PcfEntry *
pcf_file_lookup (GHashTable *pcf_file,
                 const char *group,
                 const char *key)
{
	gpointer section;
	PcfEntry *entry = NULL;
	char *group_lower = NULL;
	char *key_lower = NULL;

	g_return_val_if_fail (pcf_file != NULL, NULL);
	g_return_val_if_fail (group != NULL, NULL);
	g_return_val_if_fail (key != NULL, NULL);

	group_lower = g_utf8_strdown (group, -1);
	section = g_hash_table_lookup (pcf_file, group_lower);
	if (section) {
		key_lower = g_utf8_strdown (key, -1);
		entry = (PcfEntry *) g_hash_table_lookup ((GHashTable *) section, key_lower);
	}

	g_free (group_lower);
	g_free (key_lower);

	return entry;
}

gboolean
pcf_file_lookup_string (GHashTable *pcf_file,
                        const char *group,
                        const char *key,
                        const char **value)
{
	PcfEntry *entry;

	g_return_val_if_fail (pcf_file != NULL, FALSE);
	g_return_val_if_fail (group != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	*value = NULL;
	entry = pcf_file_lookup (pcf_file, group, key);
	if (!entry || !entry->value || !strlen (entry->value))
		return FALSE;

	*value = entry->value;
	return TRUE;
}

gboolean
pcf_file_lookup_bool (GHashTable *pcf_file,
                      const char *group,
                      const char *key,
                      gboolean *value)
{
	const char *buf = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (pcf_file != NULL, FALSE);
	g_return_val_if_fail (group != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	*value = FALSE;
	if (!pcf_file_lookup_string (pcf_file, group, key, &buf))
		return FALSE;

	if (strlen (buf) == 1) {
		if (strcmp (buf, "1") == 0) {
			*value = TRUE;
			success = TRUE;
		} else if (strcmp (buf, "0") == 0) {
			*value = FALSE;
			success = TRUE;
		}
	} else {
		if (   !strncasecmp (buf, "yes", 3)
		    || !strncasecmp (buf, "true", 4)) {
			*value = TRUE;
			success = TRUE;
		} else if (   !strncasecmp (buf, "no", 2)
		           || !strncasecmp (buf, "false", 5)) {
			*value = FALSE;
			success = TRUE;
		}
	}

	return success;
}

gboolean
pcf_file_lookup_int (GHashTable *pcf_file,
                     const char *group,
                     const char *key,
                     gint *value)
{
	const char *buf = NULL;
	long int tmp;

	g_return_val_if_fail (pcf_file != NULL, FALSE);
	g_return_val_if_fail (group != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	*value = 0;
	if (!pcf_file_lookup_string (pcf_file, group, key, &buf))
		return FALSE;

	errno = 0;
	tmp = strtol (buf, NULL, 10);
	if ((errno == 0) && (tmp > G_MININT) && (tmp < G_MAXINT)) {
		*value = (gint) tmp;
		return TRUE;
	}

	return FALSE;
}


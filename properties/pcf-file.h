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

#ifndef PCF_FILE_H
#define PCF_FILE_H

#include <glib.h>

typedef struct PcfEntry PcfEntry;

struct PcfEntry {
	char *key;
	char *value;
	gboolean read_only;
};

GHashTable  *pcf_file_load        (const char *fname);
PcfEntry    *pcf_file_lookup      (GHashTable *pcf_file,
								   const char *group,
								   const char *key);

const char *pcf_file_lookup_value (GHashTable *pcf_file,
								   const char *group,
								   const char *key);

#endif /* PCF_FILE_H */

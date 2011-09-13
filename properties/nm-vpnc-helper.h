/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-vpnc-helper.h : Header file for nm-vpnc-helper.c
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

gboolean
key_file_get_boolean_helper (GKeyFile *keyfile,
                             const gchar *group_name,
                             const gchar *key,
                             GError **error);

gboolean
key_file_get_integer_helper (GKeyFile *keyfile,
                             const gchar *group_name,
                             const gchar *key,
                             gint *value);

gchar *
key_file_get_string_helper (GKeyFile *keyfile,
                            const gchar *group_name,
                            const gchar *key,
                            GError **error);

gboolean
key_file_has_key_helper (GKeyFile *keyfile,
                         const gchar *group_name,
                         const gchar *key);


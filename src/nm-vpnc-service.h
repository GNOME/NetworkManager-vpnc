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
 * (C) Copyright 2005 - 2012 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_VPNC_PLUGIN_H
#define NM_VPNC_PLUGIN_H

#define NM_TYPE_VPNC_PLUGIN            (nm_vpnc_plugin_get_type ())
#define NM_VPNC_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPNC_PLUGIN, NMVPNCPlugin))
#define NM_VPNC_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPNC_PLUGIN, NMVPNCPluginClass))
#define NM_IS_VPNC_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPNC_PLUGIN))
#define NM_IS_VPNC_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_VPNC_PLUGIN))
#define NM_VPNC_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPNC_PLUGIN, NMVPNCPluginClass))

typedef struct {
	NMVpnServicePlugin parent;
} NMVPNCPlugin;

typedef struct {
	NMVpnServicePluginClass parent;
} NMVPNCPluginClass;

GType nm_vpnc_plugin_get_type (void);

NMVPNCPlugin *nm_vpnc_plugin_new (const char *bus_name);

#endif /* NM_VPNC_PLUGIN_H */

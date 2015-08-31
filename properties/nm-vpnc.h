/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-vpnc.h : GNOME UI dialogs for configuring vpnc VPN connections
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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

#ifndef _NM_VPNC_H_
#define _NM_VPNC_H_

#include <glib-object.h>

#define VPNC_TYPE_EDITOR_PLUGIN            (vpnc_editor_plugin_get_type ())
#define VPNC_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), VPNC_TYPE_EDITOR_PLUGIN, VpncEditorPlugin))
#define VPNC_EDITOR_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), VPNC_TYPE_EDITOR_PLUGIN, VpncEditorPluginClass))
#define VPNC_IS_EDITOR_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), VPNC_TYPE_EDITOR_PLUGIN))
#define VPNC_IS_EDITOR_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), VPNC_TYPE_EDITOR_PLUGIN))
#define VPNC_EDITOR_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), VPNC_TYPE_EDITOR_PLUGIN, VpncEditorPluginClass))

typedef struct _VpncEditorPlugin VpncEditorPlugin;
typedef struct _VpncEditorPluginClass VpncEditorPluginClass;

struct _VpncEditorPlugin {
	GObject parent;
};

struct _VpncEditorPluginClass {
	GObjectClass parent;
};

GType vpnc_editor_plugin_get_type (void);


#define VPNC_TYPE_EDITOR            (vpnc_editor_get_type ())
#define VPNC_EDITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), VPNC_TYPE_EDITOR, VpncEditor))
#define VPNC_EDITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), VPNC_TYPE_EDITOR, VpncEditorClass))
#define VPNC_IS_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), VPNC_TYPE_EDITOR))
#define VPNC_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), VPNC_TYPE_EDITOR))
#define VPNC_EDITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), VPNC_TYPE_EDITOR, VpncEditorClass))

typedef struct _VpncEditor VpncEditor;
typedef struct _VpncEditorClass VpncEditorClass;

struct _VpncEditor {
	GObject parent;
};

struct _VpncEditorClass {
	GObjectClass parent;
};

GType vpnc_editor_get_type (void);

#endif	/* _NM_VPNC_H_ */


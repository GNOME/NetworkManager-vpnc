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
 * (C) Copyright 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include "utils.h"

#include <string.h>

#define IS_EOL(a)  (a == '\r' || a == '\n')
#define VPNC_VERSION_STR "vpnc version "

/**
 * utils_handle_output:
 * @output: buffer containing vpnc output
 * @server_message: buffer in which to store a message from the VPN server
 * @server_message_done: flag which is set to %TRUE when a server message is
 *   complete
 * @prompt_fn: function to call when vpnc (or the server) sends a request for
 *   passwords or more information
 * @prompt_fn_data: pointer to pass to @prompt_fn
 *
 * Parses new vpnc output to extract server messages and detect prompts for
 * more information.  Since vpnc can print variable numbers of bytes at a time,
 * not necessarily a complete line or block, this function should be called
 * multiple times on the same buffer.  It will return the number of bytes which
 * it consumed, and that number of bytes should be removed from the start of
 * @output.  If a request for a password or username is parsed, it will call
 * @prompt_fn with the prompt message.
 *
 * Returns: the number of bytes consumed, which should be removed from the
 * start of @output.
 **/
gsize
utils_handle_output (GString *output,
                     GString *server_message,
                     gboolean *server_message_done,
                     PromptFn prompt_fn,
                     gpointer prompt_fn_data)
{
	guint32 i;

	g_return_val_if_fail (output != NULL, 0);
	g_return_val_if_fail (server_message != NULL, 0);
	g_return_val_if_fail (server_message_done != NULL, 0);
	g_return_val_if_fail (prompt_fn != NULL, 0);

	/* vpnc output is loosely formatted, with "blocks of interest" starting with
	 * no leading whitespace, and separated by double newlines, but unfortunately
	 * it doesn't output both newlines at the same time (one newline is printed
	 * at the end of one block and a second at the start of the next block with
	 * variable time in between) and some input prompts don't print newlines at
	 * all.
	 *
	 * S5.4 xauth type check
	 *  [2011-06-03 11:11:13]
	 *
	 * Wait for token to change,          (server message line #1)
	 * then enter the new tokencode:      (server message line #2)
	 *
	 * S5.5 do xauth authentication
	 *  [2011-06-03 11:11:13]
	 * Password for VPN person@1.1.1.1:   (waits for input without newline)
	 *    size = 42, blksz = 16, padding = 6
	 *
	 * So we can't just listen for '\n\n' or we won't react immediately to
	 * input prompts or correctly process service messages.
	 *
	 * Instead we pay attention to any lines that have no leading whitespace
	 * and do not start with "S[1 - 9]".  If the line ends with ":" it is an
	 * input prompt.  If it doesn't then we cache it and wait for the next line
	 * or newline, in which case it's a server message.
	 */

	if (output->len == 0)
		return 0;

	/* Find the end of the line or the end of the string; all lines *except*
	 * prompts will be newline terminated, while prompts stop at the end of the
	 * buffer because vpnc is waiting for the input.
	 */
	for (i = 0; i < output->len; i++) {
		if (!output->str[i] || IS_EOL (output->str[i]))
			break;
	}

	/* Decide whether to stop parsing a server message, which is terminated by
	 * a single empty line or some whitespace; it looks like:
	 *
	 * <stuff>
	 *
	 * Wait for token to change,
	 * then enter the new tokencode:
	 *
	 * <more stuff>
	 */
	if (server_message->len) {
		if (g_ascii_isspace (output->str[0]) || IS_EOL (output->str[0]))
		    *server_message_done = TRUE;
	}

	if (i < output->len) {
		/* Lines starting with whitespace are debug output that we don't care
		 * about.
		 */
		if (g_ascii_isspace (output->str[0]))
			return i + 1;
	} else if (i == output->len) {
		/* Check for a prompt; it will not begin with whitespace, and will end
		 * with a ':' and no newline, because vpnc will be waiting for the response.
		 */
		if (!g_ascii_isspace (output->str[0]) &&
		    (i > 2) &&
		    (strncmp ((output->str + (i - 2)), ": ", 2) == 0)) {
			/* Note: if vpnc sent a server message ending with ':' but we
			 * happened to only read up to the ':' but not the EOL, we'll
			 * confuse the server message with an input prompt.  vpnc is not
			 * helpful here.
			 */
			prompt_fn (output->str, i, prompt_fn_data);
			return i;
		}

		/* No newline and no ending semicolon; probably a partial read so wait
		 * for more output
		 */
		return 0;
	} else
		g_assert_not_reached ();

	/* No newline at the end, wait for one */
	if (!IS_EOL (output->str[i]))
		return 0;

	/* Ignore vpnc version debug output */
	if (i >= strlen (VPNC_VERSION_STR) &&
	    strncmp (output->str, VPNC_VERSION_STR, strlen (VPNC_VERSION_STR)) == 0)
		return i + 1;

	/* Ignore vpnc debug messages like "S1 init_sockaddr" */
	if (i > 2 && output->str[0] == 'S' && g_ascii_isdigit (output->str[1]))
		return i + 1;

	/* What's left is probably a server message */
	if (*server_message_done) {
		g_string_truncate (server_message, 0);
		*server_message_done = FALSE;
	}
	g_string_append_len (server_message, output->str, i + 1);
	return i + 1;
}


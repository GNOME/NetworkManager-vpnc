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

#include <string.h>

#include "utils.h"

#include "nm-utils/nm-test-utils.h"

#define TEST_HEADER \
	GString *output;\
	guint pos = 0, num, olen, linelen;\
	gboolean message_done = FALSE;\
	GString *message = g_string_new (NULL);\
	gsize consumed;\
	const char *p;\
\
	output = g_string_sized_new (512);\
	olen = strlen (o);\
	while (pos < olen) {\
		num = g_random_int_range (0, MIN (olen - pos, 30));\
		if (num == 0)\
			num++;\
		g_string_append_len (output, o + pos, num);\
		pos += num;\
		p = strchr (output->str, '\n');\
		linelen = p ? (p - output->str) + 1 : output->len;\

#define TEST_FOOTER \
		g_string_erase (output, 0, consumed);\
	} \

#define TEST_CLEANUP \
	g_string_free (output, TRUE);\
	g_string_free (message, TRUE);


static void
test_no_prompt (const char *data, gsize dlen, gpointer user_data)
{
	g_assert_not_reached ();
}

static void
test_output_simple (void)
{
	const char *o = \
"vpnc version 0.5.3\n\
   hex_test: 00010203\n\
\n\
S1 init_sockaddr\n\
 [2011-06-03 11:11:12]\n\
S3 setup_tunnel\n\
 [2011-06-03 11:11:12]\n\
   using interface tun0\n\
\n\
S4.1 create_nonce\n\
 [2011-06-03 11:11:12]\n\
   i_cookie: 4b3e235d 02d5dcd5\n\
   i_nonce:\n\
   a1d46e05 4175bbcc 6de34f7d fc374fe4 2acb8991\n\
\n\
S4.3 AM packet_1\n\
 [2011-06-03 11:11:12]\n\
\n\
 sending: ========================>\n\
   BEGIN_PARSE\n\
   Recieved Packet Len: 1287\n\
   i_cookie: 4b3e235d 02d5dcd5\n\
   r_cookie: 00000000 00000000\n\
   payload: 01 (ISAKMP_PAYLOAD_SA)\n\
   isakmp_version: 10\n\
   exchange_type: 04 (ISAKMP_EXCHANGE_AGGRESSIVE)\n\
   flags: 00\n\
   message_id: 00000000\n\
   len: 00000507\n\
   \n\
   PARSING PAYLOAD type: 03 (ISAKMP_PAYLOAD_T)\n\
   next_type: 03 (ISAKMP_PAYLOAD_T)\n\
   length: 0028\n\
   t.number: 00\n\
   t.id: 01 (ISAKMP_IPSEC_KEY_IKE)\n\
   t.attributes.type: 000e (IKE_ATTRIB_KEY_LENGTH)\n\
   t.attributes.u.attr_16: 0100\n\
   t.attributes.type: 0001 (IKE_ATTRIB_ENC)\n\
   t.attributes.type: 000c (IKE_ATTRIB_LIFE_DURATION)\n\
   t.attributes.u.lots.length: 0004\n\
   t.attributes.u.lots.data: 0020c49b\n\
   DONE PARSING PAYLOAD type: 03 (ISAKMP_PAYLOAD_T)\n\
";

	TEST_HEADER
		/* We expect no input prompts and no server messages */
		consumed = utils_handle_output (output, message, &message_done, test_no_prompt, NULL);
		if (consumed)
			g_assert_cmpint (consumed, ==, linelen);
		g_assert_cmpint (message->len, ==, 0);
		g_assert (!message_done);
	TEST_FOOTER

	g_assert_cmpstr (message->str, ==, "");
	g_assert_cmpint (message->len, ==, 0);

	TEST_CLEANUP
}

static void
test_output_message (void)
{
	const char *o = \
"S5.4 xauth type check\n\
 [2011-06-03 11:11:13]\n\
\n\
Wait for token to change,\n\
then enter the new tokencode:\n\
\n\
S5.5 do xauth authentication\n\
 [2011-06-03 11:11:13]\n\
";
	const char *expected_message = "Wait for token to change,\nthen enter the new tokencode:\n";

	TEST_HEADER
		/* We expect a server message but no input prompts */
		consumed = utils_handle_output (output, message, &message_done, test_no_prompt, NULL);
		if (consumed)
			g_assert_cmpint (consumed, ==, linelen);

		if (message_done)
			g_assert_cmpstr (message->str, ==, expected_message);
	TEST_FOOTER

	g_assert (message_done);
	TEST_CLEANUP
}

static void
test_output_message_oneline (void)
{
	const char *o = \
"S5.3 type-is-xauth check\n\
 [2013-06-27 11:24:50]\n\
\n\
S5.4 xauth type check\n\
 [2013-06-27 11:24:50]\n\
Enter Username and Password.\n\
\n\
S5.5 do xauth reply\n\
 [2013-06-27 11:24:50]\n\
";
	const char *expected_message = "Enter Username and Password.\n";

	TEST_HEADER
		/* We expect a server message but no input prompts */
		consumed = utils_handle_output (output, message, &message_done, test_no_prompt, NULL);
		if (consumed)
			g_assert_cmpint (consumed, ==, linelen);

		if (message_done)
			g_assert_cmpstr (message->str, ==, expected_message);
	TEST_FOOTER

	g_assert (message_done);
	TEST_CLEANUP
}

static void
test_has_prompt (const char *data, gsize dlen, gpointer user_data)
{
	g_assert_cmpstr (data, ==, (const char *) user_data);
}

static void
test_output_prompt (void)
{
	const char *o = \
"S5.5 do xauth authentication\n\
 [2011-06-03 11:11:13]\n\
Password for VPN person@1.1.1.1: ";

	const char *expected_prompt = "Password for VPN person@1.1.1.1: ";

	TEST_HEADER
		/* We expect an input prompt but no server message */
		consumed = utils_handle_output (output, message, &message_done, test_has_prompt, (gpointer) expected_prompt);
		if (consumed)
			g_assert_cmpint (consumed, ==, linelen);

		g_assert_cmpint (message->len, ==, 0);
		g_assert (!message_done);
	TEST_FOOTER

	TEST_CLEANUP
}

static void
test_output_message_and_prompt (void)
{
	const char *o = \
"Wait for token to change,\n\
then enter the new tokencode:\n\
\n\
Password for VPN person@1.1.1.1: ";

	const char *expected_prompt = "Password for VPN person@1.1.1.1: ";
	const char *expected_message = "Wait for token to change,\nthen enter the new tokencode:\n";

	TEST_HEADER
		/* We expect an input prompt but no server message */
		consumed = utils_handle_output (output, message, &message_done, test_has_prompt, (gpointer) expected_prompt);
		if (consumed)
			g_assert_cmpint (consumed, ==, linelen);
	TEST_FOOTER

	g_assert_cmpstr (message->str, ==, expected_message);
	g_assert (message_done);

	TEST_CLEANUP
}

static void
test_output_message_and_prompt_debug (void)
{
	const char *o = \
"S5.3 type-is-xauth check\n\
 [2011-06-03 11:11:13]\n\
\n\
S5.4 xauth type check\n\
 [2011-06-03 11:11:13]\n\
\n\
Wait for token to change,\n\
then enter the new tokencode:\n\
\n\
S5.5 do xauth authentication\n\
 [2011-06-03 11:11:13]\n\
Password for VPN person@1.1.1.1: ";

	const char *expected_prompt = "Password for VPN person@1.1.1.1: ";
	const char *expected_message = "Wait for token to change,\nthen enter the new tokencode:\n";

	TEST_HEADER
		/* We expect an input prompt but no server message */
		consumed = utils_handle_output (output, message, &message_done, test_has_prompt, (gpointer) expected_prompt);
		if (consumed)
			g_assert_cmpint (consumed, ==, linelen);
	TEST_FOOTER

	g_assert_cmpstr (message->str, ==, expected_message);
	g_assert (message_done);

	TEST_CLEANUP
}

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func ("/output/simple", test_output_simple);
	g_test_add_func ("/output/message", test_output_message);
	g_test_add_func ("/output/message-oneline", test_output_message_oneline);
	g_test_add_func ("/output/prompt", test_output_prompt);
	g_test_add_func ("/output/message-and-prompt", test_output_message_and_prompt);
	g_test_add_func ("/output/message-and-prompt-debug", test_output_message_and_prompt_debug);

	return g_test_run ();
}


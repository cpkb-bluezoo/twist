/* Copyright (C) 2026 Chris Burdess <dog@gnu.org>

   This file is part of twist.

   twist is free software: you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   twist is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public
   License along with this program.  If not, see
   <https://www.gnu.org/licenses/>.  */

#include "fuzz.h"

/* SASL mechanisms answering a server's challenges, and HTTP Digest answering
   a challenge in a header.  The first byte picks the mechanism; the input
   is the challenge, given to the mechanism and then again.  */

static const char *const mechs[] = {
  "PLAIN", "LOGIN", "CRAM-MD5", "SCRAM-SHA-256", "XOAUTH2", "OAUTHBEARER",
  "EXTERNAL", "ANONYMOUS"
};

const char *const fuzz_tokens[] = {
  "realm=", "nonce=", "qop=", "auth", "auth-int", "algorithm=", "MD5", "SHA-256",
  "opaque=", "stale=", "Digest ", "\"", ",", "r=", "s=", "i=", "c=", "p=", "n=", NULL
};

void
fuzz_seeds (void (*add) (const void *, size_t))
{
  static const char *seeds[] = {
    "\x00Username:", "\x02<123.456@host>", "\x03r=abcdef,s=c2FsdA==,i=4096",
    "\x00Digest realm=\"r\", nonce=\"n\", qop=\"auth\", algorithm=MD5, opaque=\"o\"",
    "\x01Digest realm=\"r\", nonce=\"n\", qop=\"auth,auth-int\", algorithm=SHA-256"
  };
  size_t i;

  for (i = 0; i < sizeof seeds / sizeof seeds[0]; i++)
    add (seeds[i], strlen (seeds[i] + 1) + 1);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct twist_sasl_client *c;
  int mech, round;
  char *text, *out = NULL;

  if (size == 0)
    return 0;
  mech = twist_sasl_from_name (mechs[data[0] % (sizeof mechs / sizeof mechs[0])]);
  if (mech >= 0)
    {
      c = twist_sasl_client_new (mech, "alice", "secret", "token");
      if (c != NULL)
        {
          twist_sasl_has_initial (c);
          for (round = 0; round < 3; round++)
            {
              uint8_t *reply = NULL;
              size_t rn = 0;
              int done = 0;

              if (twist_sasl_step (c, data + 1, size - 1, &reply, &rn, &done)
                  != TWIST_OK)
                {
                  free (reply);
                  break;
                }
              free (reply);
              if (done)
                break;
            }
          twist_sasl_client_free (c);
        }
    }
  text = fuzz_string (data + 1, size - 1);
  if (twist_auth_digest (text, "GET", "/index.html", "alice", "secret", 1,
                         "cnonce", &out) == TWIST_OK)
    free (out);
  free (text);
  return 0;
}

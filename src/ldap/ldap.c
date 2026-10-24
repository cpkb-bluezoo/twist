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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "twist-int.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* LDAPv3 client: simple bind, or a SASL bind through the shared
   mechanism when a bearer token is set, then one search.  Entries are
   written as LDIF as each value completes.  The BER decoder keeps a
   fixed stack and one value buffer.  */

#define LDAP_CMD 2048
#define LDAP_VAL 4096
#define LDAP_NAME 128
#define LDAP_DN 512

enum
{
  B_TAG = 0,
  B_LEN,
  B_LLEN,
  B_VAL
};

struct bout
{
  uint8_t b[LDAP_CMD];
  size_t n;
  int err;
};

struct twist_ldap
{
  struct twist_transfer *transfer;
  struct twist_mail_link link;
  struct twist_sasl_client *sasl;
  struct twist_endpoint *ep;
  int implicit_tls;
  int bind_sent;
  int finished;
  int next_id;
  int expect_id;
  int msg_id;
  int scope;
  int nattrs;
  char dn[LDAP_DN];
  char filter[LDAP_DN];
  char attrs[8][64];
  char attr[LDAP_NAME];
  int bst;
  uint8_t btag;
  size_t blen;
  int blen_left;
  size_t bval_got;
  uint8_t bval[LDAP_VAL];
  struct
  {
    uint8_t tag;
    size_t left;
  } stk[12];
  int depth;
  int in_entry;
  int in_vals;
  int in_bind;
  int in_done;
  int saw_code;
  int result_code;
  uint8_t sasl_cred[512];
  size_t sasl_cred_len;
  uint8_t cmd[LDAP_CMD];
  size_t cmdlen;
};

static void ldap_complete (struct twist_ldap *l, int err);
static int ldap_out (struct twist_ldap *l, const void *data, size_t n,
                     int reset);
static int send_search (struct twist_ldap *l);
static int emit_bytes (struct twist_ldap *l, const void *data, size_t n);

static void
ldap_complete (struct twist_ldap *l, int err)
{
  if (l == NULL || l->finished)
    return;
  l->finished = 1;
  twist_transfer_finish (l->transfer, err);
}

static int
ldap_out (struct twist_ldap *l, const void *data, size_t n, int reset)
{
  const uint8_t *p = data;

  if (reset)
    l->cmdlen = 0;
  if (l->cmdlen + n < sizeof l->cmd)
    {
      memcpy (l->cmd + l->cmdlen, p, n);
      l->cmdlen += n;
    }
  if (l->ep == NULL)
    return TWIST_OK;
  return twist_endpoint_send (l->ep, p, n);
}

static int
flush_bind (struct twist_ldap *l)
{
  if (l->bind_sent || l->ep == NULL || l->cmdlen == 0)
    return TWIST_OK;
  l->bind_sent = 1;
  return twist_endpoint_send (l->ep, l->cmd, l->cmdlen);
}

static void
put (struct bout *o, unsigned c)
{
  if (o->err || o->n >= sizeof o->b)
    {
      o->err = 1;
      return;
    }
  o->b[o->n++] = (uint8_t) c;
}

static void
put_len (struct bout *o, size_t len)
{
  if (len < 128)
    put (o, len);
  else if (len < 256)
    {
      put (o, 0x81);
      put (o, len);
    }
  else
    {
      put (o, 0x82);
      put (o, len >> 8);
      put (o, len);
    }
}

static void
put_raw (struct bout *o, uint8_t tag, const void *data, size_t n)
{
  const uint8_t *p = data;
  size_t i;

  put (o, tag);
  put_len (o, n);
  for (i = 0; i < n; i++)
    put (o, p[i]);
}

static void
put_int (struct bout *o, uint8_t tag, int v)
{
  unsigned u = (unsigned) v;
  uint8_t tmp[4];
  int start = 0;

  tmp[0] = (uint8_t) (u >> 24);
  tmp[1] = (uint8_t) (u >> 16);
  tmp[2] = (uint8_t) (u >> 8);
  tmp[3] = (uint8_t) u;
  while (start < 3 && tmp[start] == 0 && (tmp[start + 1] & 0x80) == 0)
    start++;
  put_raw (o, tag, tmp + start, (size_t) (4 - start));
}

static size_t
begin (struct bout *o, uint8_t tag)
{
  size_t mark;

  put (o, tag);
  mark = o->n;
  put (o, 0x82);
  put (o, 0);
  put (o, 0);
  return mark;
}

static void
end (struct bout *o, size_t mark)
{
  size_t len;

  if (o->err || mark + 3 > o->n)
    {
      o->err = 1;
      return;
    }
  len = o->n - (mark + 3);
  o->b[mark + 1] = (uint8_t) (len >> 8);
  o->b[mark + 2] = (uint8_t) len;
}

static int
percent (const char *in, char *out, size_t cap)
{
  size_t n = 0;

  if (in == NULL)
    in = "";
  while (*in != 0)
    {
      unsigned char c = (unsigned char) *in++;

      if (c == '%' && isxdigit ((unsigned char) in[0])
          && isxdigit ((unsigned char) in[1]))
        {
          c = (unsigned char) ((isdigit ((unsigned char) in[0])
                                ? in[0] - '0'
                                : (tolower ((unsigned char) in[0]) - 'a' + 10))
                               << 4);
          c = (unsigned char) (c
                               | (isdigit ((unsigned char) in[1])
                                  ? in[1] - '0'
                                  : (tolower ((unsigned char) in[1]) - 'a' + 10)));
          in += 2;
        }
      if (n + 1 >= cap)
        return TWIST_ERR_URL;
      out[n++] = (char) c;
    }
  out[n] = 0;
  return TWIST_OK;
}

static int
encode_filter (struct bout *o, const char *s, size_t n);

static int
encode_list (struct bout *o, const char *s, size_t n)
{
  size_t i = 0;

  while (i < n)
    {
      size_t depth = 0;
      size_t j;

      while (i < n && s[i] != '(')
        i++;
      if (i >= n)
        break;
      for (j = i; j < n; j++)
        {
          if (s[j] == '(')
            depth++;
          else if (s[j] == ')')
            {
              depth--;
              if (depth == 0)
                {
                  j++;
                  break;
                }
            }
        }
      if (depth != 0)
        return TWIST_ERR_URL;
      if (encode_filter (o, s + i, j - i) != TWIST_OK)
        return TWIST_ERR_URL;
      i = j;
    }
  return TWIST_OK;
}

static int
encode_ava (struct bout *o, uint8_t tag, const char *s, size_t n,
            size_t eq, size_t op)
{
  size_t mark = begin (o, tag);
  size_t alen = eq;
  size_t vpos = eq + op;

  while (alen > 0 && s[alen - 1] == ' ')
    alen--;
  while (vpos < n && s[vpos] == ' ')
    vpos++;
  if (alen == 0 || vpos > n)
    return TWIST_ERR_URL;
  put_raw (o, 0x04, s, alen);
  put_raw (o, 0x04, s + vpos, n - vpos);
  end (o, mark);
  return o->err ? TWIST_ERR_URL : TWIST_OK;
}

static int
encode_filter (struct bout *o, const char *s, size_t n)
{
  size_t i;

  while (n > 0 && s[0] == ' ')
    {
      s++;
      n--;
    }
  while (n > 0 && s[n - 1] == ' ')
    n--;
  if (n >= 2 && s[0] == '(' && s[n - 1] == ')')
    {
      s++;
      n -= 2;
    }
  if (n == 0)
    return TWIST_ERR_URL;
  if (s[0] == '&' || s[0] == '|' || s[0] == '!')
    {
      size_t mark = begin (o, s[0] == '&' ? 0xa0 : s[0] == '|' ? 0xa1 : 0xa2);
      int rc = s[0] == '!' ? encode_filter (o, s + 1, n - 1)
                           : encode_list (o, s + 1, n - 1);

      end (o, mark);
      return rc != TWIST_OK || o->err ? TWIST_ERR_URL : TWIST_OK;
    }
  for (i = 0; i + 1 < n; i++)
    {
      if (s[i] == '>' && s[i + 1] == '=')
        return encode_ava (o, 0xa5, s, n, i, 2);
      if (s[i] == '<' && s[i + 1] == '=')
        return encode_ava (o, 0xa6, s, n, i, 2);
    }
  for (i = 0; i < n; i++)
    if (s[i] == '=')
      break;
  if (i == 0 || i >= n)
    return TWIST_ERR_URL;
  if (i + 2 == n && s[i + 1] == '*')
    {
      size_t alen = i;

      while (alen > 0 && s[alen - 1] == ' ')
        alen--;
      if (alen == 0)
        return TWIST_ERR_URL;
      put_raw (o, 0x87, s, alen);
      return o->err ? TWIST_ERR_URL : TWIST_OK;
    }
  if (memchr (s + i + 1, '*', n - (i + 1)) != NULL)
    return TWIST_ERR_URL;
  return encode_ava (o, 0xa3, s, n, i, 1);
}

static int
take_url (struct twist_ldap *l)
{
  const char *path = l->transfer->url->path;
  const char *query = l->transfer->url->query;
  char decoded[LDAP_DN];
  const char *parts[4];
  size_t plen[4];
  int i;
  int rc;

  if (path != NULL && path[0] == '/')
    path++;
  rc = percent (path, l->dn, sizeof l->dn);
  if (rc != TWIST_OK)
    return rc;
  l->scope = 0;
  memcpy (l->filter, "(objectClass=*)", 16);
  for (i = 0; i < 4; i++)
    {
      parts[i] = NULL;
      plen[i] = 0;
    }
  if (query != NULL && query[0] != 0)
    {
      const char *s = query;
      int part = 0;

      parts[0] = s;
      for (; *s != 0 && part < 4; s++)
        if (*s == '?')
          {
            plen[part] = (size_t) (s - parts[part]);
            part++;
            if (part < 4)
              parts[part] = s + 1;
          }
      if (part < 4 && parts[part] != NULL)
        plen[part] = strlen (parts[part]);
    }
  if (parts[0] != NULL && plen[0] > 0)
    {
      size_t off = 0;

      l->nattrs = 0;
      while (off < plen[0] && l->nattrs < 8)
        {
          size_t comma = off;

          while (comma < plen[0] && parts[0][comma] != ',')
            comma++;
          if (comma > off)
            {
              char tmp[64];

              if (comma - off >= sizeof tmp)
                return TWIST_ERR_URL;
              memcpy (tmp, parts[0] + off, comma - off);
              tmp[comma - off] = 0;
              rc = percent (tmp, l->attrs[l->nattrs],
                            sizeof l->attrs[l->nattrs]);
              if (rc != TWIST_OK)
                return rc;
              if (l->attrs[l->nattrs][0] != 0)
                l->nattrs++;
            }
          off = comma + 1;
        }
    }
  if (parts[1] != NULL && plen[1] > 0)
    {
      if (plen[1] >= sizeof decoded)
        return TWIST_ERR_URL;
      memcpy (decoded, parts[1], plen[1]);
      decoded[plen[1]] = 0;
      if (strcasecmp (decoded, "base") == 0)
        l->scope = 0;
      else if (strcasecmp (decoded, "one") == 0)
        l->scope = 1;
      else if (strcasecmp (decoded, "sub") == 0)
        l->scope = 2;
      else
        return TWIST_ERR_URL;
    }
  if (parts[2] != NULL && plen[2] > 0)
    {
      if (plen[2] >= sizeof decoded)
        return TWIST_ERR_URL;
      memcpy (decoded, parts[2], plen[2]);
      decoded[plen[2]] = 0;
      rc = percent (decoded, l->filter, sizeof l->filter);
      if (rc != TWIST_OK)
        return rc;
    }
  return TWIST_OK;
}

static int
send_bind (struct twist_ldap *l, const char *mech, const uint8_t *cred,
           size_t credlen)
{
  struct bout o;
  size_t msg;
  size_t op;
  size_t sasl;
  const char *user = twist_mail_user (l->transfer);
  const char *pass = twist_mail_pass (l->transfer);

  memset (&o, 0, sizeof o);
  msg = begin (&o, 0x30);
  put_int (&o, 0x02, l->next_id);
  l->expect_id = l->next_id++;
  op = begin (&o, 0x60);
  put_int (&o, 0x02, 3);
  if (mech != NULL)
    {
      put_raw (&o, 0x04, "", 0);
      sasl = begin (&o, 0xa3);
      put_raw (&o, 0x04, mech, strlen (mech));
      if (cred != NULL)
        put_raw (&o, 0x04, cred, credlen);
      end (&o, sasl);
    }
  else
    {
      if (user == NULL)
        user = "";
      if (pass == NULL)
        pass = "";
      put_raw (&o, 0x04, user, strlen (user));
      put_raw (&o, 0x80, pass, strlen (pass));
    }
  end (&o, op);
  end (&o, msg);
  if (o.err)
    return TWIST_ERR_PROTOCOL;
  return ldap_out (l, o.b, o.n, 1);
}

static int
send_search (struct twist_ldap *l)
{
  struct bout o;
  size_t msg;
  size_t op;
  size_t alist;
  int i;
  int rc;

  memset (&o, 0, sizeof o);
  msg = begin (&o, 0x30);
  put_int (&o, 0x02, l->next_id);
  l->expect_id = l->next_id++;
  op = begin (&o, 0x63);
  put_raw (&o, 0x04, l->dn, strlen (l->dn));
  put_int (&o, 0x0a, l->scope);
  put_int (&o, 0x0a, 0);
  put_int (&o, 0x02, 0);
  put_int (&o, 0x02, 0);
  {
    static const uint8_t no = 0;

    put_raw (&o, 0x01, &no, 1);
  }
  rc = encode_filter (&o, l->filter, strlen (l->filter));
  if (rc != TWIST_OK)
    return rc;
  alist = begin (&o, 0x30);
  for (i = 0; i < l->nattrs; i++)
    put_raw (&o, 0x04, l->attrs[i], strlen (l->attrs[i]));
  end (&o, alist);
  end (&o, op);
  end (&o, msg);
  if (o.err)
    return TWIST_ERR_PROTOCOL;
  return ldap_out (l, o.b, o.n, 1);
}

static int
send_unbind (struct twist_ldap *l)
{
  struct bout o;
  size_t msg;

  memset (&o, 0, sizeof o);
  msg = begin (&o, 0x30);
  put_int (&o, 0x02, l->next_id++);
  put_raw (&o, 0x42, "", 0);
  end (&o, msg);
  if (o.err)
    return TWIST_ERR_PROTOCOL;
  return ldap_out (l, o.b, o.n, 1);
}

static int
start_auth (struct twist_ldap *l)
{
  const char *token = l->transfer->bearer;
  uint8_t *raw = NULL;
  size_t n = 0;
  int done = 0;
  int rc;

  if (token != NULL && token[0] != 0)
    {
      l->sasl = twist_sasl_client_new (TWIST_SASL_XOAUTH2,
                                       twist_mail_user (l->transfer),
                                       twist_mail_pass (l->transfer), token);
      if (l->sasl == NULL)
        return TWIST_ERR_NOMEM;
      rc = twist_sasl_step (l->sasl, NULL, 0, &raw, &n, &done);
      if (rc != TWIST_OK)
        return rc;
      rc = send_bind (l, twist_sasl_name (TWIST_SASL_XOAUTH2), raw, n);
      free (raw);
      return rc;
    }
  return send_bind (l, NULL, NULL, 0);
}

static int
emit_bytes (struct twist_ldap *l, const void *data, size_t n)
{
  struct twist_transfer *transfer = l->transfer;
  const uint8_t *p = data;
  size_t off = 0;

  if (n == 0)
    return TWIST_OK;
  if (transfer->write_cb == NULL)
    {
      twist_transfer_downloaded (transfer, n);
      return TWIST_OK;
    }
  while (off < n)
    {
      char buf[512];
      size_t chunk = n - off;
      size_t got;

      if (chunk > sizeof buf)
        chunk = sizeof buf;
      memcpy (buf, p + off, chunk);
      got = transfer->write_cb (buf, 1, chunk, transfer->write_data);
      if (got < chunk)
        return TWIST_ERR_ABORTED;
      off += chunk;
    }
  twist_transfer_downloaded (transfer, n);
  return TWIST_OK;
}

static int
is_binary (const uint8_t *p, size_t n)
{
  size_t i;

  if (n == 0)
    return 0;
  if (p[0] == ' ' || p[0] == ':' || p[0] == '<' || p[n - 1] == ' ')
    return 1;
  for (i = 0; i < n; i++)
    if (p[i] < 0x20 || p[i] > 0x7e)
      return 1;
  return 0;
}

/* An attribute description (RFC 4512): a keyword or an OID, with options
   after semicolons.  So letters, digits, dots, hyphens and semicolons, and
   nothing that would end the line or begin the value.  The name is the
   server's and goes into the output as it comes.  */
static int
valid_attr_name (const uint8_t *p, size_t n)
{
  size_t i;

  for (i = 0; i < n; i++)
    {
      uint8_t c = p[i];

      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ';'))
        return 0;
    }
  return n > 0;
}

static int
emit_line (struct twist_ldap *l, const char *name, const uint8_t *val,
           size_t n)
{
  int rc;
  int binary = is_binary (val, n);

  rc = emit_bytes (l, name, strlen (name));
  if (rc == TWIST_OK)
    rc = emit_bytes (l, binary ? ":: " : ": ", binary ? 3 : 2);
  if (rc != TWIST_OK)
    return rc;
  if (binary)
    {
      char *b64 = NULL;

      rc = twist_b64_encode (val, n, &b64);
      if (rc != TWIST_OK)
        return rc;
      rc = emit_bytes (l, b64, strlen (b64));
      free (b64);
      if (rc != TWIST_OK)
        return rc;
    }
  else if (n > 0)
    {
      rc = emit_bytes (l, val, n);
      if (rc != TWIST_OK)
        return rc;
    }
  return emit_bytes (l, "\n", 1);
}

static int
ber_int (const uint8_t *p, size_t n, int *out)
{
  unsigned v = 0;
  size_t i;

  if (n == 0 || n > 4 || (p[0] & 0x80) != 0)
    return TWIST_ERR_PROTOCOL;
  for (i = 0; i < n; i++)
    v = (v << 8) | p[i];
  *out = (int) v;
  return TWIST_OK;
}

static int finish_bind (struct twist_ldap *l);
static int finish_search (struct twist_ldap *l);

static int
on_start (struct twist_ldap *l, uint8_t tag)
{
  if (tag == 0x64 || tag == 0x61 || tag == 0x65)
    {
      if (l->msg_id != l->expect_id)
        return TWIST_ERR_PROTOCOL;
    }
  if (tag == 0x64)
    {
      l->in_entry = 1;
      l->in_vals = 0;
      l->attr[0] = 0;
    }
  else if (tag == 0x61)
    {
      l->in_bind = 1;
      l->saw_code = 0;
      l->sasl_cred_len = 0;
    }
  else if (tag == 0x65)
    {
      l->in_done = 1;
      l->saw_code = 0;
    }
  else if (tag == 0x31 && l->in_entry)
    l->in_vals = 1;
  return TWIST_OK;
}

static int
on_end (struct twist_ldap *l, uint8_t tag)
{
  if (tag == 0x31)
    l->in_vals = 0;
  else if (tag == 0x64)
    {
      l->in_entry = 0;
      l->attr[0] = 0;
      return emit_bytes (l, "\n", 1);
    }
  else if (tag == 0x61)
    {
      l->in_bind = 0;
      return finish_bind (l);
    }
  else if (tag == 0x65)
    {
      l->in_done = 0;
      return finish_search (l);
    }
  return TWIST_OK;
}

static int
on_prim (struct twist_ldap *l, uint8_t tag, const uint8_t *p, size_t n)
{
  uint8_t parent = l->depth > 0 ? l->stk[l->depth - 1].tag : 0;

  if (tag == 0x02 && l->depth == 1 && parent == 0x30)
    return ber_int (p, n, &l->msg_id);
  if (tag == 0x0a && (l->in_bind || l->in_done))
    {
      int rc = ber_int (p, n, &l->result_code);

      if (rc != TWIST_OK)
        return rc;
      l->saw_code = 1;
      l->transfer->http_code = l->result_code;
      return TWIST_OK;
    }
  if (tag == 0x87 && l->in_bind)
    {
      if (n > sizeof l->sasl_cred)
        return TWIST_ERR_PROTOCOL;
      memcpy (l->sasl_cred, p, n);
      l->sasl_cred_len = n;
      return TWIST_OK;
    }
  if (tag != 0x04 || !l->in_entry)
    return TWIST_OK;
  if (parent == 0x64)
    return emit_line (l, "dn", p, n);
  if (parent == 0x31)
    {
      if (l->attr[0] == 0)
        return TWIST_ERR_PROTOCOL;
      return emit_line (l, l->attr, p, n);
    }
  if (parent == 0x30)
    {
      if (n == 0 || n >= sizeof l->attr || !valid_attr_name (p, n))
        return TWIST_ERR_PROTOCOL;
      memcpy (l->attr, p, n);
      l->attr[n] = 0;
    }
  return TWIST_OK;
}

static int
finish_bind (struct twist_ldap *l)
{
  uint8_t *raw = NULL;
  size_t n = 0;
  int done = 0;
  int rc;

  if (!l->saw_code)
    return TWIST_ERR_PROTOCOL;
  if (l->result_code == 14)
    {
      if (l->sasl == NULL)
        return TWIST_ERR_AUTH;
      rc = twist_sasl_step (l->sasl, l->sasl_cred, l->sasl_cred_len, &raw, &n,
                            &done);
      if (rc != TWIST_OK)
        return rc;
      rc = send_bind (l, twist_sasl_name (TWIST_SASL_XOAUTH2), raw, n);
      free (raw);
      return rc;
    }
  if (l->result_code != 0)
    return TWIST_ERR_AUTH;
  twist_sasl_client_free (l->sasl);
  l->sasl = NULL;
  return send_search (l);
}

static int
finish_search (struct twist_ldap *l)
{
  int rc;

  if (!l->saw_code || l->result_code != 0)
    return TWIST_ERR_PROTOCOL;
  rc = send_unbind (l);
  if (rc != TWIST_OK)
    return rc;
  ldap_complete (l, TWIST_OK);
  return TWIST_OK;
}

static int
open_value (struct twist_ldap *l)
{
  int constructed = (l->btag & 0x20) != 0;
  int rc;

  if (l->blen > 1024u * 1024u)
    return TWIST_ERR_PROTOCOL;
  if (constructed)
    {
      if (l->depth >= (int) (sizeof l->stk / sizeof l->stk[0]))
        return TWIST_ERR_PROTOCOL;
      l->stk[l->depth].tag = l->btag;
      l->stk[l->depth].left = l->blen;
      l->depth++;
      rc = on_start (l, l->btag);
      l->bst = B_TAG;
      return rc;
    }
  if (l->blen > sizeof l->bval)
    return TWIST_ERR_PROTOCOL;
  l->bval_got = 0;
  if (l->blen == 0)
    {
      l->bst = B_TAG;
      return on_prim (l, l->btag, l->bval, 0);
    }
  l->bst = B_VAL;
  return TWIST_OK;
}

static int
pop_done (struct twist_ldap *l)
{
  while (l->depth > 0 && l->stk[l->depth - 1].left == 0)
    {
      uint8_t tag;
      int rc;

      if (l->bst != B_TAG)
        return TWIST_ERR_PROTOCOL;
      tag = l->stk[l->depth - 1].tag;
      l->depth--;
      rc = on_end (l, tag);
      if (rc != TWIST_OK)
        return rc;
    }
  return TWIST_OK;
}

static int
feed_byte (struct twist_ldap *l, uint8_t c)
{
  int i;
  int rc;

  if (l->depth > 0)
    {
      for (i = 0; i < l->depth; i++)
        {
          if (l->stk[i].left == 0)
            return TWIST_ERR_PROTOCOL;
          l->stk[i].left--;
        }
    }
  switch (l->bst)
    {
    case B_TAG:
      l->btag = c;
      l->bst = B_LEN;
      break;
    case B_LEN:
      if ((c & 0x80) != 0)
        {
          l->blen_left = c & 0x7f;
          if (l->blen_left == 0 || l->blen_left > 3)
            return TWIST_ERR_PROTOCOL;
          l->blen = 0;
          l->bst = B_LLEN;
          break;
        }
      l->blen = c;
      rc = open_value (l);
      if (rc != TWIST_OK)
        return rc;
      break;
    case B_LLEN:
      l->blen = (l->blen << 8) | c;
      l->blen_left--;
      if (l->blen_left == 0)
        {
          rc = open_value (l);
          if (rc != TWIST_OK)
            return rc;
        }
      break;
    case B_VAL:
      l->bval[l->bval_got++] = c;
      if (l->bval_got == l->blen)
        {
          l->bst = B_TAG;
          rc = on_prim (l, l->btag, l->bval, l->bval_got);
          if (rc != TWIST_OK)
            return rc;
        }
      break;
    default:
      return TWIST_ERR_PROTOCOL;
    }
  return pop_done (l);
}

size_t
twist_ldap_receive (struct twist_ldap *l, const uint8_t *data, size_t len)
{
  size_t off = 0;

  if (l == NULL)
    return 0;
  if (l->finished)
    return len;
  while (off < len && !l->finished)
    {
      {
        int rc = feed_byte (l, data[off]);

        if (rc != TWIST_OK)
          {
            ldap_complete (l, rc);
            return len;
          }
      }
      off++;
    }
  return off;
}

const uint8_t *
twist_ldap_command (const struct twist_ldap *ldap, size_t *len)
{
  if (len != NULL)
    *len = ldap != NULL ? ldap->cmdlen : 0;
  return ldap != NULL ? ldap->cmd : NULL;
}

static void
ldap_fail (void *user, int err)
{
  ldap_complete (user, err);
}

static void
ldap_connected (struct twist_endpoint *ep)
{
  struct twist_ldap *l = ep->user_data;
  int rc;

  l->ep = ep;
  if (l->implicit_tls)
    {
      rc = twist_connection_start_tls (ep->conn, l->transfer->url->host,
                                       l->transfer->verifypeer, NULL, 0,
                                       l->transfer->cainfo, l->transfer->capath, l->transfer->sslcert,
                                       l->transfer->sslkey);
      if (rc != TWIST_OK)
        ldap_complete (l, rc);
      return;
    }
  rc = flush_bind (l);
  if (rc != TWIST_OK)
    ldap_complete (l, rc);
}

static void
ldap_secure (struct twist_endpoint *ep, const char *alpn, size_t alpn_len)
{
  struct twist_ldap *l = ep->user_data;
  int rc;

  (void) alpn;
  (void) alpn_len;
  l->ep = ep;
  rc = flush_bind (l);
  if (rc != TWIST_OK)
    ldap_complete (l, rc);
}

static size_t
ldap_on_recv (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_ldap *l = ep->user_data;

  l->ep = ep;
  return twist_ldap_receive (l, data, len);
}

static void
ldap_disconnected (struct twist_endpoint *ep, int error)
{
  struct twist_ldap *l = ep->user_data;

  if (!l->finished)
    ldap_complete (l, error != TWIST_OK ? error : TWIST_ERR_CLOSED);
}

static void
ldap_error (struct twist_endpoint *ep, int error)
{
  struct twist_ldap *l = ep->user_data;

  if (!l->finished && error != TWIST_OK && error != TWIST_ERR_CLOSED)
    ldap_complete (l, error);
}

static const struct twist_protocol_handler ldap_handler = {
  ldap_connected,
  ldap_on_recv,
  ldap_disconnected,
  ldap_secure,
  ldap_error,
  NULL,
  NULL
};

void
twist_ldap_free (void *p)
{
  struct twist_ldap *l = p;

  if (l == NULL)
    return;
  twist_sasl_client_free (l->sasl);
  twist_mail_link_close (&l->link);
  free (l);
}

struct twist_ldap *
twist_ldap_new (struct twist_transfer *transfer, int live)
{
  struct twist_ldap *l;
  int rc;

  (void) live;
  if (transfer == NULL || transfer->url == NULL)
    return NULL;
  l = calloc (1, sizeof *l);
  if (l == NULL)
    return NULL;
  l->transfer = transfer;
  l->next_id = 1;
  l->implicit_tls = transfer->url->scheme != NULL
                    && strcmp (transfer->url->scheme, "ldaps") == 0;
  transfer->state = l;
  transfer->state_free = twist_ldap_free;
  rc = take_url (l);
  if (rc == TWIST_OK)
    rc = start_auth (l);
  if (rc != TWIST_OK)
    ldap_complete (l, rc);
  return l;
}

int
twist_ldap_attach (struct twist_transfer *transfer)
{
  struct twist_ldap *l;
  int rc;

  l = twist_ldap_new (transfer, 1);
  if (l == NULL)
    return TWIST_ERR_NOMEM;
  if (l->finished)
    return transfer->result;
  rc = twist_mail_link_open (&l->link, transfer, &ldap_handler, l, ldap_fail);
  if (rc != TWIST_OK)
    ldap_complete (l, rc);
  return transfer->done ? transfer->result : TWIST_OK;
}

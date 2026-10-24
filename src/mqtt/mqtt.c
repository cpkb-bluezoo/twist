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

#include <stdlib.h>
#include <string.h>

/* MQTT 3.1.1 client: CONNECT, then either PUBLISH
   the request body or SUBSCRIBE to the URL topic.  PUBLISH payloads
   are delivered as they arrive and are not stored.  Username and
   password travel in CONNECT, which is the mechanism this protocol
   has.  */

#define MQTT_CMD 2048
#define MQTT_TOPIC 512
#define MQTT_BODY 16384

enum
{
  MQ_CONNACK = 0,
  MQ_SUB,
  MQ_RUN
};

struct twist_mqtt
{
  struct twist_transfer *transfer;
  struct twist_mail_link link;
  struct twist_endpoint *ep;
  int implicit_tls;
  int connect_sent;
  int state;
  int finished;
  int in_payload;
  int pub_qos;
  unsigned pub_id;
  size_t payload_left;
  char topic[MQTT_TOPIC];
  uint8_t cmd[MQTT_CMD];
  size_t cmdlen;
};

static void mqtt_complete (struct twist_mqtt *m, int err);
static int mqtt_out (struct twist_mqtt *m, const void *data, size_t n,
                     int reset);
static int send_connect (struct twist_mqtt *m);

static void
mqtt_complete (struct twist_mqtt *m, int err)
{
  if (m == NULL || m->finished)
    return;
  m->finished = 1;
  m->in_payload = 0;
  twist_transfer_finish (m->transfer, err);
}

static int
mqtt_out (struct twist_mqtt *m, const void *data, size_t n, int reset)
{
  const uint8_t *p = data;

  if (reset)
    m->cmdlen = 0;
  if (m->cmdlen + n < sizeof m->cmd)
    {
      memcpy (m->cmd + m->cmdlen, p, n);
      m->cmdlen += n;
    }
  if (m->ep == NULL)
    return TWIST_OK;
  return twist_endpoint_send (m->ep, p, n);
}

static int
put_varint (uint8_t *b, size_t cap, size_t *n, size_t v)
{
  do
    {
      uint8_t byte = (uint8_t) (v & 0x7f);

      v >>= 7;
      if (v != 0)
        byte |= 0x80;
      if (*n >= cap)
        return TWIST_ERR_PROTOCOL;
      b[(*n)++] = byte;
    }
  while (v != 0);
  return TWIST_OK;
}

static int
put_str (uint8_t *b, size_t cap, size_t *n, const char *s)
{
  size_t len = strlen (s);

  if (len > 65535 || *n + 2 + len > cap)
    return TWIST_ERR_PROTOCOL;
  b[(*n)++] = (uint8_t) (len >> 8);
  b[(*n)++] = (uint8_t) len;
  memcpy (b + *n, s, len);
  *n += len;
  return TWIST_OK;
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

      if (c == '%' && in[0] != 0 && in[1] != 0)
        {
          int hi = in[0];
          int lo = in[1];

          if ((hi >= '0' && hi <= '9') || (hi >= 'a' && hi <= 'f')
              || (hi >= 'A' && hi <= 'F'))
            {
              int hv = hi <= '9' ? hi - '0' : (hi & ~32) - 'A' + 10;
              int lv = (lo >= '0' && lo <= '9') ? lo - '0'
                       : ((lo >= 'a' && lo <= 'f') || (lo >= 'A' && lo <= 'F'))
                         ? (lo & ~32) - 'A' + 10 : -1;

              if (lv >= 0)
                {
                  c = (unsigned char) ((hv << 4) | lv);
                  in += 2;
                }
            }
        }
      if (n + 1 >= cap)
        return TWIST_ERR_URL;
      out[n++] = (char) c;
    }
  out[n] = 0;
  return TWIST_OK;
}

static int
take_topic (struct twist_mqtt *m)
{
  const char *path = m->transfer->url->path;
  char buf[MQTT_TOPIC];
  const char *p;
  int rc;

  rc = percent (path != NULL ? path : "", buf, sizeof buf);
  if (rc != TWIST_OK)
    return rc;
  p = buf;
  if (*p == '/')
    p++;
  if (*p == 0)
    return TWIST_ERR_URL;
  if (strlen (p) >= sizeof m->topic)
    return TWIST_ERR_URL;
  memcpy (m->topic, p, strlen (p) + 1);
  return TWIST_OK;
}

static int
send_connect (struct twist_mqtt *m)
{
  uint8_t b[MQTT_CMD];
  size_t n = 0;
  size_t rem;
  const char *user = twist_mail_user (m->transfer);
  const char *pass = twist_mail_pass (m->transfer);
  int flags = 0x02;
  int rc;

  if (m->connect_sent)
    return TWIST_OK;
  if (user != NULL)
    flags |= 0x80;
  if (user != NULL && pass != NULL && pass[0] != 0)
    flags |= 0x40;
  rem = 10 + 2 + 5;
  if ((flags & 0x80) != 0)
    rem += 2 + strlen (user);
  if ((flags & 0x40) != 0)
    rem += 2 + strlen (pass);
  b[n++] = 0x10;
  rc = put_varint (b, sizeof b, &n, rem);
  if (rc != TWIST_OK)
    return rc;
  rc = put_str (b, sizeof b, &n, "MQTT");
  if (rc != TWIST_OK)
    return rc;
  if (n + 4 > sizeof b)
    return TWIST_ERR_PROTOCOL;
  b[n++] = 4;
  b[n++] = (uint8_t) flags;
  b[n++] = 0;
  b[n++] = 60;
  rc = put_str (b, sizeof b, &n, "twist");
  if (rc != TWIST_OK)
    return rc;
  if ((flags & 0x80) != 0)
    {
      rc = put_str (b, sizeof b, &n, user);
      if (rc != TWIST_OK)
        return rc;
    }
  if ((flags & 0x40) != 0)
    {
      rc = put_str (b, sizeof b, &n, pass);
      if (rc != TWIST_OK)
        return rc;
    }
  m->state = MQ_CONNACK;
  return mqtt_out (m, b, n, 1);
}

static int
flush_connect (struct twist_mqtt *m)
{
  if (m->connect_sent || m->ep == NULL || m->cmdlen == 0)
    return TWIST_OK;
  m->connect_sent = 1;
  return twist_endpoint_send (m->ep, m->cmd, m->cmdlen);
}

static int
deliver (struct twist_mqtt *m, const uint8_t *data, size_t len)
{
  struct twist_transfer *transfer = m->transfer;
  size_t off = 0;

  if (len == 0)
    return TWIST_OK;
  if (transfer->write_cb == NULL)
    {
      twist_transfer_downloaded (transfer, len);
      return TWIST_OK;
    }
  while (off < len)
    {
      char buf[512];
      size_t chunk = len - off;
      size_t n;

      if (chunk > sizeof buf)
        chunk = sizeof buf;
      memcpy (buf, data + off, chunk);
      n = transfer->write_cb (buf, 1, chunk, transfer->write_data);
      if (n < chunk)
        return TWIST_ERR_ABORTED;
      off += chunk;
    }
  twist_transfer_downloaded (transfer, len);
  return TWIST_OK;
}

static int
body_len (struct twist_transfer *transfer, const uint8_t **ptr,
          uint8_t **owned,
          size_t *len)
{
  *owned = NULL;
  *ptr = NULL;
  *len = 0;
  if (transfer->postfields != NULL)
    {
      *ptr = (const uint8_t *) transfer->postfields;
      if (transfer->postfieldsize_set && transfer->postfieldsize >= 0)
        *len = (size_t) transfer->postfieldsize;
      else
        *len = strlen (transfer->postfields);
      return TWIST_OK;
    }
  if (transfer->read_cb == NULL)
    return TWIST_OK;
  *owned = malloc (MQTT_BODY);
  if (*owned == NULL)
    return TWIST_ERR_NOMEM;
  while (*len < MQTT_BODY)
    {
      size_t room = MQTT_BODY - *len;
      size_t n = transfer->read_cb ((char *) (*owned + *len), 1,
                                    room > 512 ? 512 : room,
                                    transfer->read_data);

      if (n == 0)
        break;
      if (n > room)
        {
          free (*owned);
          *owned = NULL;
          return TWIST_ERR_ABORTED;
        }
      *len += n;
    }
  if (*len == MQTT_BODY)
    {
      char extra;
      size_t n = transfer->read_cb (&extra, 1, 1, transfer->read_data);

      if (n != 0)
        {
          free (*owned);
          *owned = NULL;
          return TWIST_ERR_PROTOCOL;
        }
    }
  *ptr = *owned;
  return TWIST_OK;
}

static int
after_connack (struct twist_mqtt *m)
{
  uint8_t hdr[8 + MQTT_TOPIC];
  size_t n = 0;
  size_t tlen = strlen (m->topic);
  int rc;

  if (m->transfer->postfields != NULL || m->transfer->read_cb != NULL)
    {
      const uint8_t *payload = NULL;
      uint8_t *owned = NULL;
      size_t plen = 0;
      size_t off = 0;
      static const uint8_t disc[] = { 0xe0, 0x00 };

      rc = body_len (m->transfer, &payload, &owned, &plen);
      if (rc != TWIST_OK)
        return rc;
      twist_progress_ul_size (m->transfer, (long long) plen);
      hdr[n++] = 0x30;
      rc = put_varint (hdr, sizeof hdr, &n, 2 + tlen + plen);
      if (rc == TWIST_OK)
        rc = put_str (hdr, sizeof hdr, &n, m->topic);
      if (rc == TWIST_OK)
        rc = mqtt_out (m, hdr, n, 1);
      while (rc == TWIST_OK && off < plen)
        {
          size_t chunk = plen - off;

          if (chunk > 512)
            chunk = 512;
          rc = mqtt_out (m, payload + off, chunk, 0);
          off += chunk;
        }
      free (owned);
      if (rc != TWIST_OK)
        return rc;
      twist_progress_uploaded (m->transfer, plen);
      rc = mqtt_out (m, disc, sizeof disc, 0);
      if (rc != TWIST_OK)
        return rc;
      mqtt_complete (m, TWIST_OK);
      return TWIST_OK;
    }
  hdr[n++] = 0x82;
  rc = put_varint (hdr, sizeof hdr, &n, 2 + 2 + tlen + 1);
  if (rc != TWIST_OK)
    return rc;
  hdr[n++] = 0x00;
  hdr[n++] = 0x01;
  rc = put_str (hdr, sizeof hdr, &n, m->topic);
  if (rc != TWIST_OK)
    return rc;
  if (n >= sizeof hdr)
    return TWIST_ERR_PROTOCOL;
  hdr[n++] = 0;
  m->state = MQ_SUB;
  return mqtt_out (m, hdr, n, 1);
}

static int
on_packet (struct twist_mqtt *m, unsigned type, const uint8_t *body,
           size_t n)
{
  if (type == 2)
    {
      unsigned code;

      if (m->state != MQ_CONNACK || n != 2)
        return TWIST_ERR_PROTOCOL;
      code = body[1];
      m->transfer->http_code = (long) code;
      if (code != 0)
        return code == 4 || code == 5 ? TWIST_ERR_AUTH : TWIST_ERR_PROTOCOL;
      return after_connack (m);
    }
  if (type == 9)
    {
      if (m->state != MQ_SUB || n < 3)
        return TWIST_ERR_PROTOCOL;
      if (body[2] == 0x80)
        return TWIST_ERR_PROTOCOL;
      m->state = MQ_RUN;
      return TWIST_OK;
    }
  if (type == 13)
    return TWIST_OK;
  if (type == 14)
    {
      mqtt_complete (m, TWIST_OK);
      return TWIST_OK;
    }
  return TWIST_ERR_PROTOCOL;
}

static int
end_publish (struct twist_mqtt *m)
{
  if (m->pub_qos == 1)
    {
      uint8_t ack[4];

      ack[0] = 0x40;
      ack[1] = 0x02;
      ack[2] = (uint8_t) (m->pub_id >> 8);
      ack[3] = (uint8_t) m->pub_id;
      return mqtt_out (m, ack, sizeof ack, 0);
    }
  if (m->pub_qos > 1)
    return TWIST_ERR_PROTOCOL;
  return TWIST_OK;
}

static int
take_varint (const uint8_t *p, size_t n, size_t *val, size_t *used)
{
  size_t v = 0;
  size_t shift = 0;
  size_t i;

  for (i = 0; i < 4 && i < n; i++)
    {
      v |= (size_t) (p[i] & 0x7f) << shift;
      if ((p[i] & 0x80) == 0)
        {
          *val = v;
          *used = i + 1;
          return 1;
        }
      shift += 7;
    }
  if (i == 4)
    return -1;
  return 0;
}

size_t
twist_mqtt_receive (struct twist_mqtt *m, const uint8_t *data, size_t len)
{
  size_t off = 0;

  if (m == NULL)
    return 0;
  if (m->finished)
    return len;
  while (off < len && !m->finished)
    {
      const uint8_t *p;
      size_t avail;
      size_t remaining = 0;
      size_t vused = 0;
      size_t hdr;
      unsigned type;
      unsigned flags;
      int got;

      if (m->in_payload)
        {
          size_t n = len - off;
          int rc;

          if (n > m->payload_left)
            n = m->payload_left;
          rc = deliver (m, data + off, n);
          if (rc != TWIST_OK)
            {
              mqtt_complete (m, rc);
              return len;
            }
          off += n;
          m->payload_left -= n;
          if (m->payload_left == 0)
            {
              m->in_payload = 0;
              rc = end_publish (m);
              if (rc != TWIST_OK)
                {
                  mqtt_complete (m, rc);
                  return len;
                }
            }
          continue;
        }
      avail = len - off;
      p = data + off;
      if (avail < 2)
        return off;
      type = (unsigned) (p[0] >> 4);
      flags = (unsigned) (p[0] & 0x0f);
      got = take_varint (p + 1, avail - 1, &remaining, &vused);
      if (got < 0)
        {
          mqtt_complete (m, TWIST_ERR_PROTOCOL);
          return len;
        }
      if (got == 0)
        {
          if (avail > 5)
            {
              mqtt_complete (m, TWIST_ERR_PROTOCOL);
              return len;
            }
          return off;
        }
      hdr = 1 + vused;
      if (type == 3)
        {
          size_t tlen;
          size_t vhdr;
          unsigned qos = (flags >> 1) & 3;

          if (qos == 3 || (m->state != MQ_SUB && m->state != MQ_RUN))
            {
              mqtt_complete (m, TWIST_ERR_PROTOCOL);
              return len;
            }
          if (avail < hdr + 2)
            {
              if (avail > 2048)
                {
                  mqtt_complete (m, TWIST_ERR_PROTOCOL);
                  return len;
                }
              return off;
            }
          tlen = ((size_t) p[hdr] << 8) | p[hdr + 1];
          if (tlen > 1024)
            {
              mqtt_complete (m, TWIST_ERR_PROTOCOL);
              return len;
            }
          vhdr = 2 + tlen + (qos > 0 ? 2 : 0);
          if (vhdr > remaining || avail < hdr + vhdr)
            {
              if (vhdr > remaining || avail > 2048)
                {
                  mqtt_complete (m, TWIST_ERR_PROTOCOL);
                  return len;
                }
              return off;
            }
          m->pub_qos = (int) qos;
          m->pub_id = 0;
          if (qos > 0)
            m->pub_id = ((unsigned) p[hdr + 2 + tlen] << 8)
                        | p[hdr + 3 + tlen];
          off += hdr + vhdr;
          m->payload_left = remaining - vhdr;
          if (m->payload_left == 0)
            {
              int rc = end_publish (m);

              if (rc != TWIST_OK)
                {
                  mqtt_complete (m, rc);
                  return len;
                }
            }
          else
            m->in_payload = 1;
          continue;
        }
      if (flags != 0 || remaining > 256)
        {
          mqtt_complete (m, TWIST_ERR_PROTOCOL);
          return len;
        }
      if (avail < hdr + remaining)
        {
          if (avail > 512)
            {
              mqtt_complete (m, TWIST_ERR_PROTOCOL);
              return len;
            }
          return off;
        }
      {
        int rc = on_packet (m, type, p + hdr, remaining);

        if (rc != TWIST_OK)
          {
            mqtt_complete (m, rc);
            return len;
          }
      }
      off += hdr + remaining;
    }
  return off;
}

const uint8_t *
twist_mqtt_command (const struct twist_mqtt *mqtt, size_t *len)
{
  if (len != NULL)
    *len = mqtt != NULL ? mqtt->cmdlen : 0;
  return mqtt != NULL ? mqtt->cmd : NULL;
}

static void
mqtt_fail (void *user, int err)
{
  mqtt_complete (user, err);
}

static void
mqtt_connected (struct twist_endpoint *ep)
{
  struct twist_mqtt *m = ep->user_data;
  int rc;

  m->ep = ep;
  if (m->implicit_tls)
    {
      rc = twist_connection_start_tls (ep->conn, m->transfer->url->host,
                                       m->transfer->verifypeer, NULL, 0,
                                       m->transfer->cainfo, m->transfer->capath, m->transfer->sslcert,
                                       m->transfer->sslkey);
      if (rc != TWIST_OK)
        mqtt_complete (m, rc);
      return;
    }
  rc = flush_connect (m);
  if (rc != TWIST_OK)
    mqtt_complete (m, rc);
}

static void
mqtt_secure (struct twist_endpoint *ep, const char *alpn, size_t alpn_len)
{
  struct twist_mqtt *m = ep->user_data;
  int rc;

  (void) alpn;
  (void) alpn_len;
  m->ep = ep;
  rc = flush_connect (m);
  if (rc != TWIST_OK)
    mqtt_complete (m, rc);
}

static size_t
mqtt_on_recv (struct twist_endpoint *ep, const uint8_t *data, size_t len)
{
  struct twist_mqtt *m = ep->user_data;

  m->ep = ep;
  return twist_mqtt_receive (m, data, len);
}

static void
mqtt_disconnected (struct twist_endpoint *ep, int error)
{
  struct twist_mqtt *m = ep->user_data;

  if (!m->finished)
    mqtt_complete (m, error != TWIST_OK ? error : TWIST_ERR_CLOSED);
}

static void
mqtt_error (struct twist_endpoint *ep, int error)
{
  struct twist_mqtt *m = ep->user_data;

  if (!m->finished && error != TWIST_OK && error != TWIST_ERR_CLOSED)
    mqtt_complete (m, error);
}

static const struct twist_protocol_handler mqtt_handler = {
  mqtt_connected,
  mqtt_on_recv,
  mqtt_disconnected,
  mqtt_secure,
  mqtt_error,
  NULL,
  NULL
};

void
twist_mqtt_free (void *p)
{
  struct twist_mqtt *m = p;

  if (m == NULL)
    return;
  twist_mail_link_close (&m->link);
  free (m);
}

struct twist_mqtt *
twist_mqtt_new (struct twist_transfer *transfer, int live)
{
  struct twist_mqtt *m;
  int rc;

  (void) live;
  if (transfer == NULL || transfer->url == NULL)
    return NULL;
  m = calloc (1, sizeof *m);
  if (m == NULL)
    return NULL;
  m->transfer = transfer;
  m->implicit_tls = transfer->url->scheme != NULL
                    && strcmp (transfer->url->scheme, "mqtts") == 0;
  transfer->state = m;
  transfer->state_free = twist_mqtt_free;
  rc = take_topic (m);
  if (rc == TWIST_OK && m->ep == NULL)
    rc = send_connect (m);
  if (rc != TWIST_OK)
    mqtt_complete (m, rc);
  return m;
}

int
twist_mqtt_attach (struct twist_transfer *transfer)
{
  struct twist_mqtt *m;
  int rc;

  m = twist_mqtt_new (transfer, 1);
  if (m == NULL)
    return TWIST_ERR_NOMEM;
  if (m->finished)
    return transfer->result;
  rc = twist_mail_link_open (&m->link, transfer, &mqtt_handler, m, mqtt_fail);
  if (rc != TWIST_OK)
    mqtt_complete (m, rc);
  return transfer->done ? transfer->result : TWIST_OK;
}

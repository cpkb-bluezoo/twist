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

#include "check.h"
#include "twist-int.h"

#include <stdlib.h>
#include <string.h>

/* The route to a target: what the intermediary is for it (forward, a tunnel
   of TCP or of UDP, none), how it is reached, and what is said to it.  The
   rules are curl's: an http:// target is forwarded and everything else is
   tunnelled, -p tunnels the first too, SOCKS always tunnels; and a proxy that
   has been found not to forward is tunnelled to.  */

static struct twist_transfer *
transfer_for (const char *url, const char *proxy)
{
  struct twist_transfer *t = twist_transfer_new ();

  check (t != NULL, "transfer");
  check (twist_url_parse_int (url, &t->url) == TWIST_OK, "url");
  if (proxy != NULL)
    twist_transfer_setopt (t, TWISTOPT_PROXY, proxy);
  twist_transfer_setopt (t, TWISTOPT_NOPROXY, "");
  return t;
}

/* The plan for URL through PROXY, as role, hop and neg.  */
static int
plan (struct twist_transfer *t, int udp, int *hop, int *neg)
{
  struct twist_route r;
  int rc = twist_route_plan (t, t->url->scheme, udp, &r);
  int role = rc == TWIST_OK ? r.role : -1;

  if (hop != NULL)
    *hop = r.hop;
  if (neg != NULL)
    *neg = r.neg;
  twist_route_free (&r);
  return role;
}

static void
test_plan (void)
{
  struct twist_transfer *t;
  int hop = -1, neg = -1;
  struct twist_route r;

  t = transfer_for ("http://example.org/", NULL);
  check (plan (t, 0, &hop, &neg) == TWIST_ROUTE_DIRECT, "no proxy: direct");
  twist_transfer_free (t);

  t = transfer_for ("http://example.org/", "http://p:3128");
  check (plan (t, 0, &hop, &neg) == TWIST_ROUTE_FORWARD && hop == TWIST_HOP_TCP
         && neg == TWIST_NEG_NONE, "http target, http proxy: forward");
  check (twist_route_plan (t, "http", 0, &r) == TWIST_OK
         && strcmp (r.host, "p") == 0 && r.port == 3128
         && r.kind == TWIST_PROXY_HTTP, "and the proxy is named");
  twist_route_free (&r);
  twist_transfer_free (t);

  t = transfer_for ("https://example.org/", "http://p:3128");
  check (plan (t, 0, &hop, &neg) == TWIST_ROUTE_TCP_TUNNEL
         && hop == TWIST_HOP_TCP && neg == TWIST_NEG_CONNECT,
         "https target, http proxy: CONNECT");
  twist_transfer_free (t);

  t = transfer_for ("http://example.org/", "https://p");
  check (plan (t, 0, &hop, &neg) == TWIST_ROUTE_FORWARD && hop == TWIST_HOP_TLS
         && neg == TWIST_NEG_NONE, "http target, https proxy: forward over TLS");
  twist_transfer_free (t);

  t = transfer_for ("https://example.org/", "https://p");
  check (plan (t, 0, &hop, &neg) == TWIST_ROUTE_TCP_TUNNEL
         && hop == TWIST_HOP_TLS && neg == TWIST_NEG_CONNECT,
         "https target, https proxy: CONNECT over TLS");
  twist_transfer_free (t);

  t = transfer_for ("ws://example.org/", "http://p");
  check (plan (t, 0, NULL, NULL) == TWIST_ROUTE_FORWARD, "ws is forwarded as http is");
  twist_transfer_free (t);

  t = transfer_for ("ftp://example.org/f", "http://p");
  check (plan (t, 0, &hop, &neg) == TWIST_ROUTE_TCP_TUNNEL
         && neg == TWIST_NEG_CONNECT, "a protocol that is not HTTP: a tunnel");
  twist_transfer_free (t);
  t = transfer_for ("smtp://example.org/", "https://p");
  check (plan (t, 0, &hop, &neg) == TWIST_ROUTE_TCP_TUNNEL
         && hop == TWIST_HOP_TLS, "and over an https proxy");
  twist_transfer_free (t);
}

static void
test_socks (void)
{
  static const struct
  {
    const char *proxy;
    int neg;
  } cases[] = {
    { "socks5://p", TWIST_NEG_SOCKS5 }, { "socks5h://p", TWIST_NEG_SOCKS5H },
    { "socks4://p", TWIST_NEG_SOCKS4 }, { "socks4a://p", TWIST_NEG_SOCKS4A }
  };
  size_t i;

  for (i = 0; i < sizeof cases / sizeof cases[0]; i++)
    {
      static const char *const urls[] = { "http://h/", "https://h/", "ftp://h/" };
      size_t j;

      for (j = 0; j < 3; j++)
        {
          struct twist_transfer *t = transfer_for (urls[j], cases[i].proxy);
          int hop = -1, neg = -1;

          check (plan (t, 0, &hop, &neg) == TWIST_ROUTE_TCP_TUNNEL
                 && hop == TWIST_HOP_TCP && neg == cases[i].neg,
                 "SOCKS is a tunnel, whatever the target");
          twist_transfer_free (t);
        }
    }
}

static void
test_proxytunnel (void)
{
  struct twist_transfer *t = transfer_for ("http://h/", "http://p");
  int hop = -1, neg = -1;

  twist_transfer_setopt (t, TWISTOPT_HTTPPROXYTUNNEL, 1L);
  check (plan (t, 0, &hop, &neg) == TWIST_ROUTE_TCP_TUNNEL
         && neg == TWIST_NEG_CONNECT, "-p: an http target is tunnelled");
  twist_transfer_free (t);
  t = transfer_for ("http://h/", "https://p");
  twist_transfer_setopt (t, TWISTOPT_HTTPPROXYTUNNEL, 1L);
  check (plan (t, 0, &hop, &neg) == TWIST_ROUTE_TCP_TUNNEL
         && hop == TWIST_HOP_TLS, "-p over an https proxy");
  twist_transfer_free (t);
  t = transfer_for ("http://h/", NULL);
  twist_transfer_setopt (t, TWISTOPT_HTTPPROXYTUNNEL, 1L);
  check (plan (t, 0, NULL, NULL) == TWIST_ROUTE_DIRECT, "-p with no proxy: direct");
  twist_transfer_free (t);
}

static void
test_udp (void)
{
  struct twist_transfer *t = transfer_for ("https://h/", "https://p");
  int hop = -1, neg = -1;
  struct twist_route r;

  check (plan (t, 1, &hop, &neg) == TWIST_ROUTE_UDP_TUNNEL
         && hop == TWIST_HOP_TLS && neg == TWIST_NEG_CONNECT_UDP,
         "HTTP/3 through an https proxy: CONNECT-UDP");
  twist_transfer_free (t);
  t = transfer_for ("https://h/", "http://p");
  check (twist_route_plan (t, "https", 1, &r) == TWIST_ERR_UNSUPPORTED,
         "HTTP/3 through an http proxy: not possible");
  twist_route_free (&r);
  twist_transfer_free (t);
  t = transfer_for ("https://h/", "socks5://p");
  check (twist_route_plan (t, "https", 1, &r) == TWIST_ERR_UNSUPPORTED,
         "nor through SOCKS");
  twist_route_free (&r);
  twist_transfer_free (t);
}

static void
test_bad (void)
{
  struct twist_transfer *t = transfer_for ("http://h/", "gopher://p");
  struct twist_route r;

  check (twist_route_plan (t, "http", 0, &r) == TWIST_ERR_UNSUPPORTED,
         "a kind of proxy that is not spoken");
  twist_route_free (&r);
  twist_transfer_free (t);
}

static void
test_learned (void)
{
  struct twist_runtime *rt = twist_runtime_new ();
  struct twist_transfer *a, *b, *c;
  struct twist_route r;

  a = transfer_for ("http://h/", "http://p:3128");
  a->runtime = rt;
  check (twist_route_plan (a, "http", 0, &r) == TWIST_OK
         && r.role == TWIST_ROUTE_FORWARD, "forwarded at first");
  twist_route_remember_no_forward (a, &r);
  twist_route_free (&r);
  check (plan (a, 0, NULL, NULL) == TWIST_ROUTE_TCP_TUNNEL,
         "after it is found not to forward: a tunnel");
  b = transfer_for ("http://other/", "http://p:3128");
  b->runtime = rt;
  check (plan (b, 0, NULL, NULL) == TWIST_ROUTE_TCP_TUNNEL,
         "for any target through that proxy");
  c = transfer_for ("http://h/", "http://q:3128");
  c->runtime = rt;
  check (plan (c, 0, NULL, NULL) == TWIST_ROUTE_FORWARD,
         "and for no other proxy");
  twist_transfer_free (a);
  twist_transfer_free (b);
  twist_transfer_free (c);
  /* A transfer outside a runtime remembers nothing, and breaks nothing.  */
  a = transfer_for ("http://h/", "http://p:3128");
  twist_route_plan (a, "http", 0, &r);
  twist_route_remember_no_forward (a, &r);
  twist_route_free (&r);
  check (plan (a, 0, NULL, NULL) == TWIST_ROUTE_FORWARD, "no runtime, no memory");
  twist_transfer_free (a);
  twist_runtime_free (rt);
}

int
main (void)
{
  test_plan ();
  test_socks ();
  test_proxytunnel ();
  test_udp ();
  test_bad ();
  test_learned ();
  return tests_finish ();
}

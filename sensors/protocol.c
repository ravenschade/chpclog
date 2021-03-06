/*
 * ws protocol handler plugin for "lws-minimal-pmd-bulk"
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The protocol shows how to send and receive bulk messages over a ws connection
 * that optionally may have the permessage-deflate extension negotiated on it.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>

/*
 * We will produce a large ws message either from this text repeated many times,
 * or from 0x40 + a 6-bit pseudorandom number
 */


/* this is how much we will send each time the connection is writable */
#define MESSAGE_CHUNK_SIZE (4 * 1024)
#define MESSAGE_SIZE (1000000 * 1024)

/* one of these is created for each client connecting to us */

struct per_session_data__minimal_pmd_bulk {
  int position_tx, position_rx;
  uint64_t rng_rx, rng_tx;
};

struct vhd_minimal_pmd_bulk {
  struct lws_context *context;
  struct lws_vhost *vhost;
  struct lws *client_wsi;

  int *interrupted;
  int *options;
};

static uint64_t rng(uint64_t *r)
{
        *r ^= *r << 21;
        *r ^= *r >> 35;
        *r ^= *r << 4;

        return *r;
}

static int
connect_client(struct vhd_minimal_pmd_bulk *vhd)
{
  struct lws_client_connect_info i;

  memset(&i, 0, sizeof(i));

  i.context = vhd->context;
  i.port = 7681;
  i.address = "localhost";
  i.path = "/";
  i.host = i.address;
  i.origin = i.address;
  i.ssl_connection = LCCSCF_USE_SSL;
  i.vhost = vhd->vhost;
  i.protocol = "lws-minimal-pmd-bulk";
  i.pwsi = &vhd->client_wsi;

  return !lws_client_connect_via_info(&i);
}

static void
schedule_callback(struct lws *wsi, int reason, int secs)
{
  lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
    lws_get_protocol(wsi), reason, secs);
}

static int
callback_minimal_pmd_bulk(struct lws *wsi, enum lws_callback_reasons reason,
        void *user, void *in, size_t len)
{
  struct per_session_data__minimal_pmd_bulk *pss =
      (struct per_session_data__minimal_pmd_bulk *)user;
  struct vhd_minimal_pmd_bulk *vhd = (struct vhd_minimal_pmd_bulk *)
      lws_protocol_vh_priv_get(lws_get_vhost(wsi),
        lws_get_protocol(wsi));
  uint8_t buf[LWS_PRE + MESSAGE_CHUNK_SIZE], *start = &buf[LWS_PRE], *p;
  int n, m, flags;

  switch (reason) {

  case LWS_CALLBACK_PROTOCOL_INIT:
    vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
        lws_get_protocol(wsi),
        sizeof(struct vhd_minimal_pmd_bulk));
    if (!vhd)
      return -1;

    vhd->context = lws_get_context(wsi);
    vhd->vhost = lws_get_vhost(wsi);

    /* get the pointer to "interrupted" we were passed in pvo */
    vhd->interrupted = (int *)lws_pvo_search(
      (const struct lws_protocol_vhost_options *)in,
      "interrupted")->value;
    vhd->options = (int *)lws_pvo_search(
      (const struct lws_protocol_vhost_options *)in,
      "options")->value;

    if (connect_client(vhd))
      schedule_callback(wsi, LWS_CALLBACK_USER, 1);
    break;

  case LWS_CALLBACK_CLIENT_ESTABLISHED:
    pss->rng_tx = 4;
    pss->rng_rx = 4;
    lws_callback_on_writable(wsi);
    break;

  case LWS_CALLBACK_CLIENT_WRITEABLE:

    /*
     * when we connect, we will send the server a message
     */

    if (pss->position_tx == MESSAGE_SIZE)
      break;

    /* fill up one chunk's worth of message content */

    p = start;
    n = MESSAGE_CHUNK_SIZE;
    if (n > MESSAGE_SIZE - pss->position_tx)
      n = MESSAGE_SIZE - pss->position_tx;

    flags = lws_write_ws_flags(LWS_WRITE_BINARY, !pss->position_tx,
             pss->position_tx + n == MESSAGE_SIZE);

    /*
     * select between producing compressible repeated text,
     * or uncompressible PRNG output
     */

      pss->position_tx += n;
      while (n--)
        *p++ = rng(&pss->rng_tx);

    n = lws_ptr_diff(p, start);
    m = lws_write(wsi, start, n, flags);
    if (m < n) {
      lwsl_err("ERROR %d writing ws\n", m);
      return -1;
    }
    if (pss->position_tx != MESSAGE_SIZE) /* if more to do... */
      lws_callback_on_writable(wsi);
    else
      /* if we sent and received everything */
      if (pss->position_rx == MESSAGE_SIZE)
        *vhd->interrupted = 2;
    break;

  case LWS_CALLBACK_CLIENT_RECEIVE:

    /*
     * When we connect, the server will send us a message too
     */

    lwsl_user("LWS_CALLBACK_CLIENT_RECEIVE: %4d (rpp %5d, last %d)\n",
      (int)len, (int)lws_remaining_packet_payload(wsi),
      lws_is_final_fragment(wsi));

    p = (uint8_t *)in;
    pss->position_rx += len;
    while (len--)
      if (*p++ != (uint8_t)rng(&pss->rng_rx)) {
        lwsl_user("echo'd data doesn't match\n");
        return -1;
      }

    /* if we sent and received everything */

    if (pss->position_rx == MESSAGE_SIZE &&
        pss->position_tx == MESSAGE_SIZE)
      *vhd->interrupted = 2;

    break;

  case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
    lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
       in ? (char *)in : "(null)");
    vhd->client_wsi = NULL;
    schedule_callback(wsi, LWS_CALLBACK_USER, 1);
    break;

  case LWS_CALLBACK_CLIENT_CLOSED:
    vhd->client_wsi = NULL;
    schedule_callback(wsi, LWS_CALLBACK_USER, 1);
    break;

  /* rate-limited client connect retries */

  case LWS_CALLBACK_USER:
    lwsl_notice("%s: LWS_CALLBACK_USER\n", __func__);
    if (connect_client(vhd))
      schedule_callback(wsi, LWS_CALLBACK_USER, 1);
    break;

  default:
    break;
  }

  return 0;
}

#define LWS_PLUGIN_PROTOCOL_MINIMAL_PMD_BULK \
  { \
    "lws-minimal-pmd-bulk", \
    callback_minimal_pmd_bulk, \
    sizeof(struct per_session_data__minimal_pmd_bulk), \
    4096, \
    0, NULL, 0 \
  }

#if !defined (LWS_PLUGIN_STATIC)

/* boilerplate needed if we are built as a dynamic plugin */

static const struct lws_protocols protocols[] = {
  LWS_PLUGIN_PROTOCOL_MINIMAL_PMD_BULK
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_minimal_pmd_bulk(struct lws_context *context,
             struct lws_plugin_capability *c)
{
  if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
    lwsl_err("Plugin API %d, library API %d", LWS_PLUGIN_API_MAGIC,
       c->api_magic);
    return 1;
  }

  c->protocols = protocols;
  c->count_protocols = ARRAY_SIZE(protocols);
  c->extensions = NULL;
  c->count_extensions = 0;

  return 0;
}

LWS_EXTERN LWS_VISIBLE int
destroy_protocol_minimal_pmd_bulk(struct lws_context *context)
{
  return 0;
}
#endif

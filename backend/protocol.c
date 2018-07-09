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
#include <openssl/ssl.h>
#endif

#include <string.h>

/*
 * We will produce a large ws message either from this text repeated many times,
 * or from 0x40 + a 6-bit pseudorandom number
 */

/* this reflects the length of the string above */
#define REPEAT_STRING_LEN 1337
/* this is the total size of the ws message we will send */
#define MESSAGE_SIZE (100 * REPEAT_STRING_LEN)
/* this is how much we will send each time the connection is writable */
#define MESSAGE_CHUNK_SIZE (8 * 1024)

/* one of these is created for each client connecting to us */

struct per_session_data__minimal_pmd_bulk {
  int position_tx, position_rx;
  uint64_t rng_rx, rng_tx;
};

struct vhd_minimal_pmd_bulk {
        int *interrupted;
        /*
         * b0 = 1: test compressible text, = 0: test uncompressible binary
         * b1 = 1: send as a single blob, = 0: send as fragments
         */
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
callback_minimal_pmd_bulk(struct lws *wsi, enum lws_callback_reasons reason,
        void *user, void *in, size_t len)
{
  struct per_session_data__minimal_pmd_bulk *pss =
      (struct per_session_data__minimal_pmd_bulk *)user;
        struct vhd_minimal_pmd_bulk *vhd = (struct vhd_minimal_pmd_bulk *)
                        lws_protocol_vh_priv_get(lws_get_vhost(wsi),
                                lws_get_protocol(wsi));
  uint8_t buf[LWS_PRE + MESSAGE_SIZE], *start = &buf[LWS_PRE], *p;
  int n, m, flags, olen, amount;

  switch (reason) {
        case LWS_CALLBACK_PROTOCOL_INIT:
                vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
                                lws_get_protocol(wsi),
                                sizeof(struct vhd_minimal_pmd_bulk));
                if (!vhd)
                        return -1;

                /* get the pointer to "interrupted" we were passed in pvo */
                vhd->interrupted = (int *)lws_pvo_search(
                        (const struct lws_protocol_vhost_options *)in,
                        "interrupted")->value;
                vhd->options = (int *)lws_pvo_search(
                        (const struct lws_protocol_vhost_options *)in,
                        "options")->value;
                break;

  case LWS_CALLBACK_ESTABLISHED:
    pss->rng_tx = 4;
    pss->rng_rx = 4;
    lws_callback_on_writable(wsi);
    break;

  case LWS_CALLBACK_SERVER_WRITEABLE:
    if (pss->position_tx == MESSAGE_SIZE)
      break;

    amount = MESSAGE_CHUNK_SIZE;
    if ((*vhd->options) & 2) {
      amount = MESSAGE_SIZE;
      lwsl_user("(writing as one blob of %d)\n", amount);
    }

    /* fill up one chunk's worth of message content */

    p = start;
    n = amount;
    if (n > MESSAGE_SIZE - pss->position_tx)
      n = MESSAGE_SIZE - pss->position_tx;

    flags = lws_write_ws_flags(LWS_WRITE_BINARY, !pss->position_tx,
             pss->position_tx + n == MESSAGE_SIZE);

    /*
     * select between producing compressible repeated text,
     * or uncompressible PRNG output
     */

    if (*vhd->options & 1) {
      while (n) {
        size_t s;

        m = pss->position_tx % REPEAT_STRING_LEN;
        s = REPEAT_STRING_LEN - m;
        if (s > (size_t)n)
          s = n;
        memcpy(p, &redundant_string[m], s);
        pss->position_tx += s;
        p += s;
        n -= s;
      }
    } else {
      pss->position_tx += n;
      while (n--)
        *p++ = rng(&pss->rng_tx);
    }

    n = lws_ptr_diff(p, start);
    m = lws_write(wsi, start, n, flags);
    lwsl_user("LWS_CALLBACK_SERVER_WRITEABLE: wrote %d\n", n);
    if (m < n) {
      lwsl_err("ERROR %d writing ws\n", n);
      return -1;
    }
    if (pss->position_tx != MESSAGE_SIZE) /* if more to do... */
      lws_callback_on_writable(wsi);
    break;

  case LWS_CALLBACK_RECEIVE:
//    lwsl_user("LWS_CALLBACK_RECEIVE: %4d (pss->pos=%d, rpp %5d, last %d)\n",
//        (int)len, (int)pss->position_rx, (int)lws_remaining_packet_payload(wsi),
//        lws_is_final_fragment(wsi));
    olen = len;

    if (*vhd->options & 1) {
      while (len) {
        size_t s;
        m = pss->position_rx % REPEAT_STRING_LEN;
        s = REPEAT_STRING_LEN - m;
        if (s > len)
          s = len;
        if (memcmp(in, &redundant_string[m], s)) {
          lwsl_user("echo'd data doesn't match\n");
          return -1;
        }
        pss->position_rx += s;
        in += s;
        len -= s;
      }
    } else {
      p = (uint8_t *)in;
      pss->position_rx += len;
      while (len--) {
        if (*p++ != (uint8_t)rng(&pss->rng_rx)) {
          lwsl_user("echo'd data doesn't match: 0x%02X 0x%02X (%d)\n",
            *(p - 1), (int)(0x40 + (pss->rng_rx & 0x3f)),
            (int)((pss->position_rx - olen) + olen - len));
          lwsl_hexdump_notice(in, olen);
          return -1;
        }
      }
      if (pss->position_rx == MESSAGE_SIZE)
        pss->position_rx = 0;
    }
    break;
  case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
    {
      if(!len){
        return 1;
      }
      lwsl_user("LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION\n");
      X509* x509 = SSL_get_peer_certificate((SSL*)in);
      int n=SSL_get_verify_result((SSL*)in);
      if(n!=X509_V_OK){
        return 1;
      }

      return 0;
    }
    break;
  case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
    {
      lwsl_user("LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS\n");
      char* crl_path = "ca/intermediate/crl/intermediate.crl.pem"; // path to root certifcate file
      char* ca_path="ca/intermediate/certs/ca-chain.cert.pem";
   

      SSL_CTX *ctx = (SSL_CTX*) user;
      /* Enable CRL checking of the server certificate */
      X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
      X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
      SSL_CTX_set1_param(ctx, param);

      n = SSL_CTX_load_verify_locations( ctx, ca_path, NULL );
      if( n != 1 ){
          char errbuf[256];
          n = ERR_get_error();
          lwsl_err("LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS: SSL error: %s (%d)\n", ERR_error_string(n, errbuf), n);
          return 1;
      }


      X509_STORE *store = SSL_CTX_get_cert_store(ctx);
      X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
      int n = X509_load_cert_crl_file(lookup, crl_path, X509_FILETYPE_PEM);
    
      if (n != 1) {
          char errbuf[256];
          n = ERR_get_error();
          lwsl_err("LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS: SSL error: %s (%d)\n", ERR_error_string(n, errbuf), n);
          return 1;
      }
      X509_VERIFY_PARAM_free(param);
    }
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

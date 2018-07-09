/*
 * ws protocol handler plugin for "lws-minimal-server-echo"
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

#include <openssl/ssl.h>

#include <string.h>

#define RING_DEPTH 40960

/* one of these created for each message */

struct msg {
  void *payload; /* is malloc'd */
  size_t len;
  char binary;
  char first;
  char final;
};

struct per_session_data__minimal_server_echo {
  struct lws_ring *ring;
  uint32_t msglen;
  uint32_t tail;
  uint8_t completed:1;
  uint8_t flow_controlled:1;
};

struct vhd_minimal_server_echo {
  struct lws_context *context;
  struct lws_vhost *vhost;

  int *interrupted;
  int *options;
};

static void
__minimal_destroy_message(void *_msg)
{
  struct msg *msg = _msg;

  free(msg->payload);
  msg->payload = NULL;
  msg->len = 0;
}
#include <assert.h>
static int
callback_minimal_server_echo(struct lws *wsi, enum lws_callback_reasons reason,
        void *user, void *in, size_t len)
{
  struct per_session_data__minimal_server_echo *pss =
      (struct per_session_data__minimal_server_echo *)user;
  struct vhd_minimal_server_echo *vhd = (struct vhd_minimal_server_echo *)
      lws_protocol_vh_priv_get(lws_get_vhost(wsi),
        lws_get_protocol(wsi));
  const struct msg *pmsg;
  struct msg amsg;
  int n, m, flags;

  switch (reason) {

  case LWS_CALLBACK_PROTOCOL_INIT:
    vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
        lws_get_protocol(wsi),
        sizeof(struct vhd_minimal_server_echo));
    if (!vhd)
      return -1;

    vhd->context = lws_get_context(wsi);
    vhd->vhost = lws_get_vhost(wsi);

    /* get the pointers we were passed in pvo */

    vhd->interrupted = (int *)lws_pvo_search(
      (const struct lws_protocol_vhost_options *)in,
      "interrupted")->value;
    vhd->options = (int *)lws_pvo_search(
      (const struct lws_protocol_vhost_options *)in,
      "options")->value;
    break;

  case LWS_CALLBACK_ESTABLISHED:
    lwsl_user("LWS_CALLBACK_ESTABLISHED\n");
    pss->ring = lws_ring_create(sizeof(struct msg), RING_DEPTH,
              __minimal_destroy_message);
    if (!pss->ring)
      return 1;
    pss->tail = 0;
    break;

  case LWS_CALLBACK_SERVER_WRITEABLE:

    lwsl_user("LWS_CALLBACK_SERVER_WRITEABLE\n");
    if(0==1){
      do {
        pmsg = lws_ring_get_element(pss->ring, &pss->tail);
        if (!pmsg) {
          lwsl_user(" (nothing in ring)\n");
          break;
        }

        flags = lws_write_ws_flags(
              pmsg->binary ? LWS_WRITE_BINARY : LWS_WRITE_TEXT,
              pmsg->first, pmsg->final);

        /* notice we allowed for LWS_PRE in the payload already */
        m = lws_write(wsi, pmsg->payload + LWS_PRE, pmsg->len, flags);
        if (m < (int)pmsg->len) {
          lwsl_err("ERROR %d writing to ws socket\n", m);
          return -1;
        }

        lwsl_user(" wrote %d: flags: 0x%x first: %d final %d\n",
            m, flags, pmsg->first, pmsg->final);

        lws_ring_consume_single_tail(pss->ring, &pss->tail, 1);

      } while (lws_ring_get_element(pss->ring, &pss->tail) &&
         !lws_send_pipe_choked(wsi));
    }else{
      do {
        lws_ring_consume_single_tail(pss->ring, &pss->tail, 1);

      } while (lws_ring_get_element(pss->ring, &pss->tail) &&
         !lws_send_pipe_choked(wsi));
    }

    /* more to do for us? */
    if (lws_ring_get_element(pss->ring, &pss->tail))
      /* come back as soon as we can write more */
      lws_callback_on_writable(wsi);

    if (pss->flow_controlled &&
        (int)lws_ring_get_count_free_elements(pss->ring) > RING_DEPTH - 5) {
      lws_rx_flow_control(wsi, 1);
      pss->flow_controlled = 0;
    }

    if ((*vhd->options & 1) && pmsg && pmsg->final)
      pss->completed = 1;
    break;

  case LWS_CALLBACK_RECEIVE:

    lwsl_user("LWS_CALLBACK_RECEIVE: %4d (rpp %5d, first %d, "
        "last %d, bin %d, msglen %d (+ %d = %d))\n",
        (int)len, (int)lws_remaining_packet_payload(wsi),
        lws_is_first_fragment(wsi),
        lws_is_final_fragment(wsi),
        lws_frame_is_binary(wsi), pss->msglen, (int)len,
        (int)pss->msglen + (int)len);

    if (len) {
      ;
      puts((const char *)in);
      lwsl_hexdump_notice(in, len);
    }

    amsg.first = lws_is_first_fragment(wsi);
    amsg.final = lws_is_final_fragment(wsi);
    amsg.binary = lws_frame_is_binary(wsi);
    n = (int)lws_ring_get_count_free_elements(pss->ring);
    if (!n) {
      lwsl_user("dropping!\n");
      break;
    }

    if (amsg.final)
      pss->msglen = 0;
    else
      pss->msglen += len;

    amsg.len = len;
    /* notice we over-allocate by LWS_PRE */
    amsg.payload = malloc(LWS_PRE + len);
    if (!amsg.payload) {
      lwsl_user("OOM: dropping\n");
      break;
    }

    memcpy((char *)amsg.payload + LWS_PRE, in, len);
    if (!lws_ring_insert(pss->ring, &amsg, 1)) {
      __minimal_destroy_message(&amsg);
      lwsl_user("dropping!\n");
      break;
    }
    lws_callback_on_writable(wsi);

    if (n < 3 && !pss->flow_controlled) {
      pss->flow_controlled = 1;
      lws_rx_flow_control(wsi, 0);
    }
    break;

  case LWS_CALLBACK_CLOSED:
    lwsl_user("LWS_CALLBACK_CLOSED\n");
    lws_ring_destroy(pss->ring);

    if (*vhd->options & 1) {
      if (!*vhd->interrupted)
        *vhd->interrupted = 1 + pss->completed;
      lws_cancel_service(lws_get_context(wsi));
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

#define LWS_PLUGIN_PROTOCOL_MINIMAL_SERVER_ECHO \
  { \
    "lws-minimal-server-echo", \
    callback_minimal_server_echo, \
    sizeof(struct per_session_data__minimal_server_echo), \
    1024, \
    0, NULL, 0 \
  }

#if !defined (LWS_PLUGIN_STATIC)

/* boilerplate needed if we are built as a dynamic plugin */

static const struct lws_protocols protocols[] = {
  LWS_PLUGIN_PROTOCOL_MINIMAL_server_echo
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_minimal_server_echo(struct lws_context *context,
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
destroy_protocol_minimal_server_echo(struct lws_context *context)
{
  return 0;
}
#endif

/*
 * lws-minimal-ws-server-echo
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a ws server that echoes back what it was sent, in a way
 * compatible with autobahn -m fuzzingclient
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define LWS_PLUGIN_STATIC
#include "protocol.c"

static struct lws_protocols protocols[] = {
  LWS_PLUGIN_PROTOCOL_MINIMAL_SERVER_ECHO,
  { NULL, NULL, 0, 0 } /* terminator */
};

static int interrupted, port = 7681, options;

/* pass pointers to shared vars to the protocol */

static const struct lws_protocol_vhost_options pvo_options = {
  NULL,
  NULL,
  "options",    /* pvo name */
  (void *)&options  /* pvo value */
};

static const struct lws_protocol_vhost_options pvo_interrupted = {
  &pvo_options,
  NULL,
  "interrupted",    /* pvo name */
  (void *)&interrupted  /* pvo value */
};

static const struct lws_protocol_vhost_options pvo = {
  NULL,        /* "next" pvo linked-list */
  &pvo_interrupted,    /* "child" pvo linked-list */
  "lws-minimal-server-echo",  /* protocol name we belong to on this vhost */
  ""        /* ignored */
};
static const struct lws_extension extensions[] = {
  {
    "permessage-deflate",
    lws_extension_callback_pm_deflate,
    "permessage-deflate"
     "; client_no_context_takeover"
     "; client_max_window_bits"
  },
  { NULL, NULL, NULL /* terminator */ }
};

void sigint_handler(int sig)
{
  interrupted = 1;
}

int main(int argc, const char **argv)
{
  struct lws_context_creation_info info;
  struct lws_context *context;

  char cert_path[1024] = "";
  char key_path[1024] = "";
  char ca_path[1024] = "";

  const char *p;
  int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO | LLL_INFO
      /* for LLL_ verbosity above NOTICE to be built into lws,
       * lws must have been configured and built with
       * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
      /* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
      /* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
      /* | LLL_DEBUG */;

  signal(SIGINT, sigint_handler);

  if ((p = lws_cmdline_option(argc, argv, "-d")))
    logs = atoi(p);

  lws_set_log_level(logs, NULL);
  lwsl_user("LWS minimal ws client echo + permessage-deflate + multifragment bulk message\n");
  lwsl_user("   lws-minimal-ws-client-echo [-n (no exts)] [-p port] [-o (once)]\n");


  if ((p = lws_cmdline_option(argc, argv, "-p")))
    port = atoi(p);

  if (lws_cmdline_option(argc, argv, "-o"))
    options |= 1;

  memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
  info.port = port;
  info.protocols = protocols;
  info.pvo = &pvo;
  if (!lws_cmdline_option(argc, argv, "-n"))
    info.extensions = extensions;
  info.pt_serv_buf_size = 32 * 1024;
  info.options = LWS_SERVER_OPTION_VALIDATE_UTF8;
  info.options|= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
  info.options|= LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
  info.options |= LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS;
  info.ssl_cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:"
			       "ECDHE-RSA-AES256-GCM-SHA384:"
			       "DHE-RSA-AES256-GCM-SHA384:"
			       "ECDHE-RSA-AES256-SHA384:"
			       "HIGH:!aNULL:!eNULL:!EXPORT:"
			       "!DES:!MD5:!PSK:!RC4:!HMAC_SHA1:"
			       "!SHA1:!DHE-RSA-AES128-GCM-SHA256:"
			       "!DHE-RSA-AES128-SHA256:"
			       "!AES128-GCM-SHA256:"
			       "!AES128-SHA256:"
			       "!DHE-RSA-AES256-SHA256:"
			       "!AES256-GCM-SHA384:"
			       "!AES256-SHA256";

  info.ssl_ca_filepath = "../backend/ca/intermediate/certs/ca-chain.cert.pem";
  info.ssl_cert_filepath = "./ca/intermediate/certs/localhost.cert.pem";
  info.ssl_private_key_filepath = "./ca/intermediate/private/localhost.key.pem";
  
  context = lws_create_context(&info);
  if (!context) {
    lwsl_err("lws init failed\n");
    return 1;
  }

  while (n >= 0 && !interrupted)
    n = lws_service(context, 1000);

  lws_context_destroy(context);

  lwsl_user("Completed %s\n", interrupted == 2 ? "OK" : "failed");

  return interrupted != 2;
}

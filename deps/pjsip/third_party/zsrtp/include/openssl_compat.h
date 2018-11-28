#ifndef _OPENSSL_COMPAT
#define _OPENSSL_COMPAT

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined (LIBRESSL_VERSION_NUMBER)
static HMAC_CTX *HMAC_CTX_new(void)
{
   HMAC_CTX *ctx = (HMAC_CTX*)OPENSSL_malloc(sizeof(*ctx));
   if (ctx != NULL)
       HMAC_CTX_init(ctx);
   return ctx;
}

static void HMAC_CTX_free(HMAC_CTX *ctx)
{
   if (ctx != NULL) {
       HMAC_CTX_cleanup(ctx);
       OPENSSL_free(ctx);
   }
}
#endif

#endif

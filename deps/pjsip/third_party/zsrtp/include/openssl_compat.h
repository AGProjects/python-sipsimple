#ifndef _OPENSSL_COMPAT
#define _OPENSSL_COMPAT

#include <openssl/hmac.h>

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
static HMAC_CTX *HMAC_CTX_new(void)
{
    HMAC_CTX *ctx = (HMAC_CTX*)OPENSSL_malloc(sizeof(HMAC_CTX));
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

static int HMAC_CTX_reset(HMAC_CTX *ctx)
{
    HMAC_CTX_init(ctx);
    return 1;
}
#endif

#endif

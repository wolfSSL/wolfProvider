/* wp_ecx_exch.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfProvider.
 *
 * wolfProvider is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfProvider is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
 */

#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#if defined(WP_HAVE_X25519) || defined(WP_HAVE_X448)

/** Common key agree function pointer. */
typedef int (*WP_ECX_AGREE)(void* private_key, void* public_key, byte* out,
    word32* outlen);

/**
 * Alternative ECDH key exchange context.
 */
typedef struct wp_EcxCtx {
    /** Provider context - useful for getting library context. */
    WOLFPROV_CTX* provCtx;

    /** Reference to our key. */
    wp_Ecx* key;
    /** Reference to peer's public key. */
    wp_Ecx* peer;
} wp_EcxCtx;


/**
 * Create a new base alt ECDH key exchange context object.
 *
 * @param [in] provCtx  Provider context.
 * @return  ECDH key exchange object on success.
 * @return  NULL on failure.
 */
static wp_EcxCtx* wp_ecx_newctx(WOLFPROV_CTX* provCtx)
{
    wp_EcxCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }

    return ctx;
}

/**
 * Free the alt ECDH key exchange context object.
 *
 * @param [in, out] ctx  Alt ECDH key exchange context object.
 */
static void wp_ecx_freectx(wp_EcxCtx* ctx)
{
    if (ctx != NULL) {
        wp_ecx_free(ctx->peer);
        wp_ecx_free(ctx->key);
        OPENSSL_free(ctx);
    }
}

/**
 * Duplicate an alt ECDH key exchange context object.
 *
 * @param [in] src  Alt ECDH key exchange context object.
 * @return  Alt ECDH key exchange context object on success.
 * @return  NULL on failure.
 */
static wp_EcxCtx* wp_ecx_dupctx(wp_EcxCtx* src)
{
    wp_EcxCtx* dst = NULL;

    if (wolfssl_prov_is_running()) {
        dst = OPENSSL_zalloc(sizeof(*dst));
    }
    if (dst != NULL) {
        int ok = 1;

        dst->provCtx = src->provCtx;
        if ((src->key != NULL) && (!wp_ecx_up_ref(src->key))) {
            ok = 0;
        }
        else {
            dst->key = src->key;
        }
        if (ok && (src->peer != NULL) && (!wp_ecx_up_ref(src->peer))) {
            ok = 0;
        }
        else {
            dst->peer = src->peer;
        }
        if (!ok) {
            wp_ecx_free(src->key);
            OPENSSL_free(dst);
        }
    }

    return dst;
}

/**
 * Initialize the alt ECDH key exchange object with private key and parameters.
 *
 * @param [in, out] ctx     Alt ECDH key exchange context object.
 * @param [in, out] ecx     Alt EC key object. (Up referenced.)
 * @param [in]      params  Parameters like KDF info.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_init(wp_EcxCtx* ctx, wp_Ecx* ecx, const OSSL_PARAM params[])
{
    int ok = 1;

    /* No settable parameters. */
    (void)params;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (ctx->key != ecx)) {
        wp_ecx_free(ctx->key);
        ctx->key = NULL;
        if (!wp_ecx_up_ref(ecx)) {
            ok = 0;
        }
    }
    if (ok) {
        ctx->key = ecx;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the peer's public key into the alt ECDH key exchange context object.
 *
 * @param [in, out] ctx   Alt ECDH key exchange context object.
 * @param [in, out] peer  Peer's public key in alt ECDH key object.
 *                        (Up referenced.)
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_ecx_set_peer(wp_EcxCtx* ctx, wp_Ecx* peer)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok && (ctx->peer != peer)) {
        wp_ecx_free(ctx->peer);
        ctx->peer = NULL;
        if (!wp_ecx_up_ref(peer)) {
            ok = 0;
        }
    }
    if (ok) {
        ctx->peer = peer;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#ifdef WP_HAVE_X25519

/*
 * X25519
 */

/** Order of Curve25519. Subtract from secret if larger. */
const unsigned char wp_curve25519_order[] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed
};

/**
 * Derive a secret/key using X25519.
 *
 * Can put the secret through a KDF.
 *
 * @param [in]  ctx      ECX key exchange context object.
 * @param [out] secret   Buffer to hold secret/key.
 * @param [out] secLen   Length of secret/key data in bytes.
 * @param [in]  secSize  Size of buffer in bytes.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_x25519_derive(wp_EcxCtx* ctx, unsigned char* secret,
    size_t* secLen, size_t secSize)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    /* No output buffer, return secret size only. */
    if (ok && (secret == NULL)) {
        *secLen = CURVE25519_KEYSIZE;
    }
    else if (ok) {
        int rc;
        word32 len = (word32)secSize;
        int i;

        rc = wc_curve25519_shared_secret(wp_ecx_get_key(ctx->key),
            wp_ecx_get_key(ctx->peer), secret, &len);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            for (i = 0; i < CURVE25519_KEYSIZE; i++) {
                if (secret[i] != wp_curve25519_order[i]) {
                    break;
                }
            }
            if ((i < CURVE25519_KEYSIZE) &&
                (secret[i] > wp_curve25519_order[i])) {
                int16_t carry = 0;
                for (i = CURVE25519_KEYSIZE - 1; i >= 0; i--) {
                    carry += secret[i];
                    carry -= wp_curve25519_order[i];
                    secret[i] = (unsigned char)carry;
                    carry >>= 8;
                }
            }
        }
        if (ok) {
            *secLen = len;
            /* Switch endian. */
            for (i = 0; i < (int)len / 2; i++) {
                byte t = secret[i];
                secret[i] = secret[len - 1 - i];
                secret[len - 1 - i] = t;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** Dispatch table for X25519 key exchange. */
const OSSL_DISPATCH wp_x25519_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX,    (DFUNC)wp_ecx_newctx    },
    { OSSL_FUNC_KEYEXCH_FREECTX,   (DFUNC)wp_ecx_freectx   },
    { OSSL_FUNC_KEYEXCH_DUPCTX,    (DFUNC)wp_ecx_dupctx    },
    { OSSL_FUNC_KEYEXCH_INIT,      (DFUNC)wp_ecx_init      },
    { OSSL_FUNC_KEYEXCH_DERIVE,    (DFUNC)wp_x25519_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER,  (DFUNC)wp_ecx_set_peer  },
    { 0, NULL }
};

#endif /* WP_HAVE_X25519 */

#ifdef WP_HAVE_X448

/*
 * X448
 */

/**
 * Derive a secret/key using X448.
 *
 * Can put the secret through a KDF.
 *
 * @param [in]  ctx      ECX key exchange context object.
 * @param [out] secret   Buffer to hold secret/key.
 * @param [out] secLen   Length of secret/key data in bytes.
 * @param [in]  secSize  Size of buffer in bytes.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_x448_derive(wp_EcxCtx* ctx, unsigned char* secret,
    size_t* secLen, size_t secSize)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    /* No output buffer, return secret size only. */
    if (ok && (secret == NULL)) {
        *secLen = CURVE448_KEY_SIZE;
    }
    else if (ok) {
        int rc;
        word32 len = (word32)secSize;

        rc = wc_curve448_shared_secret(wp_ecx_get_key(ctx->key),
            wp_ecx_get_key(ctx->peer), secret, &len);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            word32 i;

            *secLen = len;
            /* Switch endian. */
            for (i = 0; i < len / 2; i++) {
                byte t = secret[i];
                secret[i] = secret[len - 1 - i];
                secret[len - 1 - i] = t;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** Dispatch table for X448 key exchange. */
const OSSL_DISPATCH wp_x448_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX,    (DFUNC)wp_ecx_newctx   },
    { OSSL_FUNC_KEYEXCH_FREECTX,   (DFUNC)wp_ecx_freectx  },
    { OSSL_FUNC_KEYEXCH_DUPCTX,    (DFUNC)wp_ecx_dupctx   },
    { OSSL_FUNC_KEYEXCH_INIT,      (DFUNC)wp_ecx_init     },
    { OSSL_FUNC_KEYEXCH_DERIVE,    (DFUNC)wp_x448_derive  },
    { OSSL_FUNC_KEYEXCH_SET_PEER,  (DFUNC)wp_ecx_set_peer },
    { 0, NULL }
};

#endif /* WP_HAVE_X448 */

#endif /* WP_HAVE_X25519 || WP_HAVE_X448 */


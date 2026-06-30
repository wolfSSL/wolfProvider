/* wp_mlx_kem.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
#include <openssl/evp.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#ifdef WP_HAVE_MLKEM

#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ecc.h>

/** Classical component is X25519 (must match wp_mlx_kmgmt.c). */
#define WP_MLX_CLASSICAL_X25519     0

/**
 * Hybrid KEM context.
 */
typedef struct wp_MlxCtx {
    /** Provider context. */
    WOLFPROV_CTX* provCtx;
    /** wolfProvider hybrid key (owned reference). */
    wp_Mlx* mlx;
    /** RNG for ML-KEM encapsulation and classical key generation. */
    WC_RNG rng;
} wp_MlxCtx;


/**
 * Create a new hybrid KEM context object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New KEM context on success, NULL on failure.
 */
static wp_MlxCtx* wp_mlx_kem_newctx(WOLFPROV_CTX* provCtx)
{
    wp_MlxCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = (wp_MlxCtx*)OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        int rc = wc_InitRng(&ctx->rng);
        if (rc != 0) {
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }
    return ctx;
}

/**
 * Free a hybrid KEM context object.
 *
 * @param [in, out] ctx  KEM context. May be NULL.
 */
static void wp_mlx_kem_freectx(wp_MlxCtx* ctx)
{
    if (ctx != NULL) {
        wc_FreeRng(&ctx->rng);
        wp_mlx_free(ctx->mlx);
        OPENSSL_free(ctx);
    }
}

/**
 * Duplicate a hybrid KEM context.
 *
 * @param [in] srcCtx  Source KEM context.
 * @return  Duplicated context on success, NULL on failure.
 */
static wp_MlxCtx* wp_mlx_kem_dupctx(wp_MlxCtx* srcCtx)
{
    wp_MlxCtx* dstCtx = NULL;

    if ((!wolfssl_prov_is_running()) || (srcCtx == NULL)) {
        return NULL;
    }

    dstCtx = wp_mlx_kem_newctx(srcCtx->provCtx);
    if (dstCtx == NULL) {
        return NULL;
    }
    if (srcCtx->mlx != NULL) {
        if (!wp_mlx_up_ref(srcCtx->mlx)) {
            wp_mlx_kem_freectx(dstCtx);
            return NULL;
        }
        dstCtx->mlx = srcCtx->mlx;
    }
    return dstCtx;
}

/**
 * Initialize a hybrid KEM context with a key.
 *
 * @param [in, out] ctx     KEM context.
 * @param [in]      mlx     Hybrid key (reference taken).
 * @param [in]      params  Init-time parameters. Unused.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlx_kem_init(wp_MlxCtx* ctx, wp_Mlx* mlx,
    const OSSL_PARAM params[])
{
    (void)params;

    if ((ctx == NULL) || (mlx == NULL)) {
        return 0;
    }
    if (!wp_mlx_up_ref(mlx)) {
        return 0;
    }
    wp_mlx_free(ctx->mlx);
    ctx->mlx = mlx;
    return 1;
}

static int wp_mlx_kem_encapsulate_init(wp_MlxCtx* ctx, wp_Mlx* mlx,
    const OSSL_PARAM params[])
{
    if (!wp_mlx_has_pub(mlx)) {
        return 0;
    }
    return wp_mlx_kem_init(ctx, mlx, params);
}

static int wp_mlx_kem_decapsulate_init(wp_MlxCtx* ctx, wp_Mlx* mlx,
    const OSSL_PARAM params[])
{
    if (!wp_mlx_has_priv(mlx)) {
        return 0;
    }
    return wp_mlx_kem_init(ctx, mlx, params);
}

/**
 * Compute the classical ECDH shared secret with an ephemeral private key and
 * write the ephemeral public key (for the ciphertext).
 *
 * @param [in]  ctx     KEM context.
 * @param [out] cbuf    Buffer for the ephemeral classical public key.
 * @param [out] sbuf    Buffer for the classical shared secret.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlx_kem_classical_encap(wp_MlxCtx* ctx, unsigned char* cbuf,
    unsigned char* sbuf)
{
    int ok = 1;
    int rc;
    const wp_MlxData* data = wp_mlx_get_data(ctx->mlx);
    word32 pubLen = data->classicalPubSize;
    word32 ssLen = data->classicalShSecSize;

    if (data->classicalType == WP_MLX_CLASSICAL_X25519) {
        curve25519_key eph;

        rc = wc_curve25519_init(&eph);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            rc = wc_curve25519_make_key(&ctx->rng, CURVE25519_KEYSIZE, &eph);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_curve25519_export_public_ex(&eph, cbuf, &pubLen,
                EC25519_LITTLE_ENDIAN);
            if ((rc != 0) || (pubLen != data->classicalPubSize)) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_curve25519_shared_secret_ex(&eph,
                (curve25519_key*)wp_mlx_get_classical_key(ctx->mlx), sbuf,
                &ssLen, EC25519_LITTLE_ENDIAN);
            if ((rc != 0) || (ssLen != data->classicalShSecSize)) {
                ok = 0;
            }
        }
        wc_curve25519_free(&eph);
    }
    else {
        ecc_key eph;

        rc = wc_ecc_init(&eph);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            rc = wc_ecc_make_key_ex(&ctx->rng, 0, &eph, data->curveId);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_ecc_set_rng(&eph, &ctx->rng);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_ecc_export_x963(&eph, cbuf, &pubLen);
            if ((rc != 0) || (pubLen != data->classicalPubSize)) {
                ok = 0;
            }
        }
        if (ok) {
            PRIVATE_KEY_UNLOCK();
            rc = wc_ecc_shared_secret(&eph,
                (ecc_key*)wp_mlx_get_classical_key(ctx->mlx), sbuf, &ssLen);
            PRIVATE_KEY_LOCK();
            if ((rc != 0) || (ssLen != data->classicalShSecSize)) {
                ok = 0;
            }
        }
        wc_ecc_free(&eph);
    }
    return ok;
}

/**
 * Encapsulate: ML-KEM encaps plus classical ECDHE, concatenated per slot.
 *
 * @param [in]      ctx        KEM context.
 * @param [out]     out        Ciphertext buffer.
 * @param [in, out] outLen     On in, buffer size; on out, ciphertext length.
 * @param [out]     secret     Shared secret buffer.
 * @param [in, out] secretLen  On in, buffer size; on out, secret length.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlx_kem_encapsulate(wp_MlxCtx* ctx, unsigned char* out,
    size_t* outLen, unsigned char* secret, size_t* secretLen)
{
    int ok = 1;
    int rc;
    const wp_MlxData* data;
    size_t ctSize;
    size_t ssSize;
    int slot;
    unsigned char* mlkemCt;
    unsigned char* mlkemSs;
    unsigned char* classicalCt;
    unsigned char* classicalSs;

    if ((ctx == NULL) || (ctx->mlx == NULL)) {
        return 0;
    }
    data = wp_mlx_get_data(ctx->mlx);
    slot = data->mlkemSlot;
    ctSize = (size_t)data->mlkemCtSize + data->classicalPubSize;
    ssSize = (size_t)WP_MLKEM_SS_SIZE + data->classicalShSecSize;

    if ((out == NULL) && (secret == NULL)) {
        if (outLen != NULL) {
            *outLen = ctSize;
        }
        if (secretLen != NULL) {
            *secretLen = ssSize;
        }
        return 1;
    }
    if ((out == NULL) || (secret == NULL) || (outLen == NULL) ||
            (secretLen == NULL)) {
        return 0;
    }
    if ((*outLen < ctSize) || (*secretLen < ssSize)) {
        return 0;
    }

    /* ML-KEM piece at slot offset; classical piece in the other slot. */
    mlkemCt = out + (size_t)slot * data->classicalPubSize;
    mlkemSs = secret + (size_t)slot * data->classicalShSecSize;
    classicalCt = out + (size_t)(1 - slot) * data->mlkemCtSize;
    classicalSs = secret + (size_t)(1 - slot) * WP_MLKEM_SS_SIZE;

    rc = wc_MlKemKey_Encapsulate((MlKemKey*)wp_mlx_get_mlkem_key(ctx->mlx),
        mlkemCt, mlkemSs, &ctx->rng);
    if (rc != 0) {
        ok = 0;
    }
    if (ok) {
        ok = wp_mlx_kem_classical_encap(ctx, classicalCt, classicalSs);
    }
    if (ok) {
        *outLen = ctSize;
        *secretLen = ssSize;
    }
    else {
        /* Scrub any component shared secret already written to the caller's
         * buffer when a later component fails. */
        wc_ForceZero(secret, ssSize);
    }
    return ok;
}

/**
 * Compute the classical ECDH shared secret on the decapsulation side.
 *
 * @param [in]  ctx   KEM context.
 * @param [in]  cbuf  Peer's classical public key from the ciphertext.
 * @param [out] sbuf  Buffer for the classical shared secret.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlx_kem_classical_decap(wp_MlxCtx* ctx, const unsigned char* cbuf,
    unsigned char* sbuf)
{
    int ok = 1;
    int rc;
    const wp_MlxData* data = wp_mlx_get_data(ctx->mlx);
    word32 ssLen = data->classicalShSecSize;

    if (data->classicalType == WP_MLX_CLASSICAL_X25519) {
        curve25519_key peer;

        rc = wc_curve25519_init(&peer);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            rc = wc_curve25519_import_public_ex(cbuf, data->classicalPubSize,
                &peer, EC25519_LITTLE_ENDIAN);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_curve25519_shared_secret_ex(
                (curve25519_key*)wp_mlx_get_classical_key(ctx->mlx), &peer,
                sbuf, &ssLen, EC25519_LITTLE_ENDIAN);
            if ((rc != 0) || (ssLen != data->classicalShSecSize)) {
                ok = 0;
            }
        }
        wc_curve25519_free(&peer);
    }
    else {
        ecc_key peer;
        ecc_key* priv = (ecc_key*)wp_mlx_get_classical_key(ctx->mlx);

        rc = wc_ecc_init(&peer);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            rc = wc_ecc_import_x963_ex(cbuf, data->classicalPubSize, &peer,
                data->curveId);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_ecc_set_rng(priv, &ctx->rng);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            PRIVATE_KEY_UNLOCK();
            rc = wc_ecc_shared_secret(priv, &peer, sbuf, &ssLen);
            PRIVATE_KEY_LOCK();
            if ((rc != 0) || (ssLen != data->classicalShSecSize)) {
                ok = 0;
            }
        }
        wc_ecc_free(&peer);
    }
    return ok;
}

/**
 * Decapsulate: ML-KEM decaps plus classical ECDH, concatenated per slot.
 *
 * @param [in]      ctx     KEM context.
 * @param [out]     out     Shared secret buffer.
 * @param [in, out] outLen  On in, buffer size; on out, secret length.
 * @param [in]      in      Ciphertext.
 * @param [in]      inLen   Ciphertext length.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlx_kem_decapsulate(wp_MlxCtx* ctx, unsigned char* out,
    size_t* outLen, const unsigned char* in, size_t inLen)
{
    int ok = 1;
    int rc;
    const wp_MlxData* data;
    size_t ssSize;
    size_t ctSize;
    int slot;
    const unsigned char* mlkemCt;
    const unsigned char* classicalCt;
    unsigned char* mlkemSs;
    unsigned char* classicalSs;

    if ((ctx == NULL) || (ctx->mlx == NULL)) {
        return 0;
    }
    data = wp_mlx_get_data(ctx->mlx);
    slot = data->mlkemSlot;
    ssSize = (size_t)WP_MLKEM_SS_SIZE + data->classicalShSecSize;
    ctSize = (size_t)data->mlkemCtSize + data->classicalPubSize;

    if (out == NULL) {
        if (outLen != NULL) {
            *outLen = ssSize;
        }
        return 1;
    }
    if ((outLen == NULL) || (in == NULL)) {
        return 0;
    }
    if (*outLen < ssSize) {
        return 0;
    }
    if (inLen != ctSize) {
        return 0;
    }

    mlkemCt = in + (size_t)slot * data->classicalPubSize;
    mlkemSs = out + (size_t)slot * data->classicalShSecSize;
    classicalCt = in + (size_t)(1 - slot) * data->mlkemCtSize;
    classicalSs = out + (size_t)(1 - slot) * WP_MLKEM_SS_SIZE;

    rc = wc_MlKemKey_Decapsulate((MlKemKey*)wp_mlx_get_mlkem_key(ctx->mlx),
        mlkemSs, mlkemCt, data->mlkemCtSize);
    if (rc != 0) {
        ok = 0;
    }
    if (ok) {
        ok = wp_mlx_kem_classical_decap(ctx, classicalCt, classicalSs);
    }
    if (ok) {
        *outLen = ssSize;
    }
    else {
        /* Scrub any component shared secret already written to the caller's
         * buffer when a later component fails. */
        wc_ForceZero(out, ssSize);
    }
    return ok;
}

/* No supported params; OSSL contract is unconditional success. */
static int wp_mlx_kem_get_ctx_params(wp_MlxCtx* ctx, OSSL_PARAM* params)
{
    (void)ctx;
    (void)params;
    return 1;
}

static const OSSL_PARAM* wp_mlx_kem_gettable_ctx_params(wp_MlxCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mlx_kem_gettable[] = {
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_mlx_kem_gettable;
}

static int wp_mlx_kem_set_ctx_params(wp_MlxCtx* ctx, const OSSL_PARAM params[])
{
    (void)ctx;
    (void)params;
    return 1;
}

static const OSSL_PARAM* wp_mlx_kem_settable_ctx_params(wp_MlxCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mlx_kem_settable[] = {
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_mlx_kem_settable;
}

/** Dispatch table for the hybrid KEM (shared across all three groups). */
const OSSL_DISPATCH wp_mlx_asym_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX,             (DFUNC)wp_mlx_kem_newctx           },
    { OSSL_FUNC_KEM_FREECTX,            (DFUNC)wp_mlx_kem_freectx          },
    { OSSL_FUNC_KEM_DUPCTX,             (DFUNC)wp_mlx_kem_dupctx           },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,   (DFUNC)wp_mlx_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE,        (DFUNC)wp_mlx_kem_encapsulate      },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,   (DFUNC)wp_mlx_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE,        (DFUNC)wp_mlx_kem_decapsulate      },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS,     (DFUNC)wp_mlx_kem_get_ctx_params   },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS,
        (DFUNC)wp_mlx_kem_gettable_ctx_params                             },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,     (DFUNC)wp_mlx_kem_set_ctx_params   },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
        (DFUNC)wp_mlx_kem_settable_ctx_params                             },
    { 0, NULL }
};

#endif /* WP_HAVE_MLKEM */

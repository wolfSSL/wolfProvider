/* wp_mlkem_kem.c
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

/**
 * ML-KEM KEM context.
 */
/* FIPS 203 encapsulation entropy (m), in bytes. */
#define WP_MLKEM_IKME_SZ 32

typedef struct wp_MlKemCtx {
    /** Provider context. */
    WOLFPROV_CTX* provCtx;
    /** wolfProvider ML-KEM key (owned reference). */
    wp_MlKem* mlkem;
    /** RNG for encapsulate. */
    WC_RNG rng;
    /** Test-only encapsulation entropy (ikme); empty = use RNG. */
    unsigned char ikme[WP_MLKEM_IKME_SZ];
    /** Length of ikme (0 = not set). */
    size_t ikmeLen;
} wp_MlKemCtx;


/**
 * Create a new ML-KEM KEM context object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New KEM context on success, NULL on failure.
 */
static wp_MlKemCtx* wp_mlkem_kem_newctx(WOLFPROV_CTX* provCtx)
{
    wp_MlKemCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = (wp_MlKemCtx*)OPENSSL_zalloc(sizeof(*ctx));
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
 * Free an ML-KEM KEM context object.
 *
 * @param [in, out] ctx  KEM context. May be NULL.
 */
static void wp_mlkem_kem_freectx(wp_MlKemCtx* ctx)
{
    if (ctx != NULL) {
        wc_FreeRng(&ctx->rng);
        wp_mlkem_free(ctx->mlkem);
        /* ctx embeds the encapsulation entropy (FIPS 203 ikme); cleanse. */
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

/**
 * Duplicate an ML-KEM KEM context.
 *
 * @param [in] srcCtx  Source KEM context.
 * @return  Duplicated context on success, NULL on failure.
 */
static wp_MlKemCtx* wp_mlkem_kem_dupctx(wp_MlKemCtx* srcCtx)
{
    wp_MlKemCtx* dstCtx = NULL;

    if ((!wolfssl_prov_is_running()) || (srcCtx == NULL)) {
        return NULL;
    }

    dstCtx = wp_mlkem_kem_newctx(srcCtx->provCtx);
    if (dstCtx == NULL) {
        return NULL;
    }
    if (srcCtx->mlkem != NULL) {
        if (!wp_mlkem_up_ref(srcCtx->mlkem)) {
            wp_mlkem_kem_freectx(dstCtx);
            return NULL;
        }
        dstCtx->mlkem = srcCtx->mlkem;
    }
    return dstCtx;
}

/**
 * Initialize an ML-KEM KEM context with a key.
 *
 * @param [in, out] ctx     KEM context.
 * @param [in]      mlkem   ML-KEM key (reference taken).
 * @param [in]      params  Init-time parameters (e.g. encap ikme entropy).
 * @return  1 on success, 0 on failure.
 */
static int wp_mlkem_kem_set_ctx_params(wp_MlKemCtx* ctx,
    const OSSL_PARAM params[]);

static int wp_mlkem_kem_init(wp_MlKemCtx* ctx, wp_MlKem* mlkem,
    const OSSL_PARAM params[])
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mlkem_kem_init");
    if ((ctx == NULL) || (mlkem == NULL)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (!wp_mlkem_up_ref(mlkem)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    wp_mlkem_free(ctx->mlkem);
    ctx->mlkem = mlkem;
    /* Apply any init-time params (e.g. the ikme encap entropy). */
    ok = wp_mlkem_kem_set_ctx_params(ctx, params);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static int wp_mlkem_kem_encapsulate_init(wp_MlKemCtx* ctx, wp_MlKem* mlkem,
    const OSSL_PARAM params[])
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mlkem_kem_encapsulate_init");
    ok = wp_mlkem_kem_init(ctx, mlkem, params);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static int wp_mlkem_kem_decapsulate_init(wp_MlKemCtx* ctx, wp_MlKem* mlkem,
    const OSSL_PARAM params[])
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mlkem_kem_decapsulate_init");
    ok = wp_mlkem_kem_init(ctx, mlkem, params);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encapsulate: produce ciphertext and shared secret.
 *
 * If out or secret is NULL, just report the output sizes.
 *
 * @param [in]      ctx        KEM context.
 * @param [out]     out        Ciphertext buffer.
 * @param [in, out] outLen     On in, buffer size; on out, ciphertext length.
 * @param [out]     secret     Shared secret buffer.
 * @param [in, out] secretLen  On in, buffer size; on out, secret length.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlkem_kem_encapsulate(wp_MlKemCtx* ctx, unsigned char* out,
    size_t* outLen, unsigned char* secret, size_t* secretLen)
{
    int ok = 1;
    const wp_MlKemData* data;
    word32 ctSize;
    word32 ssSize;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mlkem_kem_encapsulate");

    if ((ctx == NULL) || (ctx->mlkem == NULL)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }

    data = wp_mlkem_get_data(ctx->mlkem);
    ctSize = wp_mlkem_data_ct_size(data);
    ssSize = WP_MLKEM_SS_SIZE;

    /* Size-only query: both output buffers NULL. A mixed-NULL request (one
     * buffer NULL, the other not) is a caller bug, not a size query. */
    if ((out == NULL) && (secret == NULL)) {
        if (outLen != NULL) {
            *outLen = ctSize;
        }
        if (secretLen != NULL) {
            *secretLen = ssSize;
        }
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
        return 1;
    }
    if ((out == NULL) || (secret == NULL) || (outLen == NULL) ||
            (secretLen == NULL)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }

    /* Reject undersized buffers before the backend runs. Returning here (not
     * falling through to the failure scrub) keeps any later wc_ForceZero in
     * bounds, since the buffer is then proven at least ssSize. */
    if (*outLen < ctSize) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (*secretLen < ssSize) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (ok) {
        int rc;
        MlKemKey* key = (MlKemKey*)wp_mlkem_get_key(ctx->mlkem);
        /* Deterministic encap from supplied entropy (ikme), else RNG. */
        if (ctx->ikmeLen == WP_MLKEM_IKME_SZ) {
            rc = wc_MlKemKey_EncapsulateWithRandom(key, out, secret, ctx->ikme,
                (int)ctx->ikmeLen);
        }
        else {
            rc = wc_MlKemKey_Encapsulate(key, out, secret, &ctx->rng);
        }
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        *outLen = ctSize;
        *secretLen = ssSize;
    }
    else {
        /* Backend failed with a buffer proven >= ssSize; scrub stays in bounds. */
        wc_ForceZero(secret, ssSize);
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decapsulate: recover shared secret from ciphertext.
 *
 * If out is NULL, just report the secret size.
 *
 * @param [in]      ctx       KEM context.
 * @param [out]     out       Shared secret buffer.
 * @param [in, out] outLen    On in, buffer size; on out, secret length.
 * @param [in]      in        Ciphertext.
 * @param [in]      inLen     Ciphertext length.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlkem_kem_decapsulate(wp_MlKemCtx* ctx, unsigned char* out,
    size_t* outLen, const unsigned char* in, size_t inLen)
{
    int ok = 1;
    const wp_MlKemData* data;
    word32 ssSize;
    word32 ctSize;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mlkem_kem_decapsulate");

    if ((ctx == NULL) || (ctx->mlkem == NULL)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }

    data = wp_mlkem_get_data(ctx->mlkem);
    ssSize = WP_MLKEM_SS_SIZE;
    ctSize = wp_mlkem_data_ct_size(data);

    if (out == NULL) {
        if (outLen != NULL) {
            *outLen = ssSize;
        }
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
        return 1;
    }
    if ((outLen == NULL) || (in == NULL)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }

    /* Reject an undersized output buffer before the backend runs, so the
     * later failure scrub of ssSize bytes is proven in bounds. */
    if (*outLen < ssSize) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (ok && (inLen != ctSize)) {
        ok = 0;
    }
    if (ok) {
        int rc = wc_MlKemKey_Decapsulate(
            (MlKemKey*)wp_mlkem_get_key(ctx->mlkem), out, in, (word32)inLen);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        *outLen = ssSize;
    }
    else {
        /* Output buffer proven >= ssSize above; scrub stays in bounds. */
        wc_ForceZero(out, ssSize);
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/* No supported params; OSSL contract is unconditional success. */
static int wp_mlkem_kem_get_ctx_params(wp_MlKemCtx* ctx, OSSL_PARAM* params)
{
    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mlkem_kem_get_ctx_params");
    (void)ctx;
    (void)params;
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

static const OSSL_PARAM* wp_mlkem_kem_gettable_ctx_params(wp_MlKemCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mlkem_kem_gettable[] = {
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_mlkem_kem_gettable;
}

/* Honor the test-only encapsulation entropy (ikme) used by ACVP KATs. */
static int wp_mlkem_kem_set_ctx_params(wp_MlKemCtx* ctx,
    const OSSL_PARAM params[])
{
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mlkem_kem_set_ctx_params");

    if (ctx == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (params == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
        return 1;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_IKME);
    if (p != NULL) {
        void* vp = ctx->ikme;
        ctx->ikmeLen = 0;
        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(ctx->ikme),
                &ctx->ikmeLen)) {
            WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
            return 0;
        }
        /* A short IKME would silently revert encapsulation from deterministic
         * to RNG; require the exact FIPS 203 size. */
        if (ctx->ikmeLen != WP_MLKEM_IKME_SZ) {
            ctx->ikmeLen = 0;
            WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
            return 0;
        }
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

static const OSSL_PARAM* wp_mlkem_kem_settable_ctx_params(wp_MlKemCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mlkem_kem_settable[] = {
        OSSL_PARAM_octet_string(OSSL_KEM_PARAM_IKME, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_mlkem_kem_settable;
}

/** Dispatch table for ML-KEM KEM (shared across all three levels). */
const OSSL_DISPATCH wp_mlkem_asym_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX,
        (DFUNC)wp_mlkem_kem_newctx                            },
    { OSSL_FUNC_KEM_FREECTX,
        (DFUNC)wp_mlkem_kem_freectx                           },
    { OSSL_FUNC_KEM_DUPCTX,
        (DFUNC)wp_mlkem_kem_dupctx                            },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
        (DFUNC)wp_mlkem_kem_encapsulate_init                  },
    { OSSL_FUNC_KEM_ENCAPSULATE,
        (DFUNC)wp_mlkem_kem_encapsulate                       },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
        (DFUNC)wp_mlkem_kem_decapsulate_init                  },
    { OSSL_FUNC_KEM_DECAPSULATE,
        (DFUNC)wp_mlkem_kem_decapsulate                       },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS,
        (DFUNC)wp_mlkem_kem_get_ctx_params                    },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS,
        (DFUNC)wp_mlkem_kem_gettable_ctx_params               },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,
        (DFUNC)wp_mlkem_kem_set_ctx_params                    },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
        (DFUNC)wp_mlkem_kem_settable_ctx_params               },
    { 0, NULL }
};

#endif /* WP_HAVE_MLKEM */

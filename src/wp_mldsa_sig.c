/* wp_mldsa_sig.c
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
#include <openssl/evp.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#ifdef WP_HAVE_MLDSA

#include <wolfssl/wolfcrypt/dilithium.h>

/**
 * ML-DSA signature context.
 *
 * ML-DSA is a pure signature (no streamed digest); digest_sign_* accumulates
 * the message in mdBuf and the one-shot signer is called in _final.
 */
typedef struct wp_MlDsaSigCtx {
    /** Provider context. */
    WOLFPROV_CTX* provCtx;
    /** wolfProvider ML-DSA key (owned reference). */
    wp_MlDsa* mldsa;
    /** RNG for signing. */
    WC_RNG rng;
    /** Buffer accumulating message bytes from digest_sign_update. */
    unsigned char* mdBuf;
    /** Length of accumulated message in bytes. */
    size_t mdLen;
    /** Capacity of mdBuf in bytes. */
    size_t mdCap;
} wp_MlDsaSigCtx;


/**
 * Append data into the streaming message buffer.
 *
 * @param [in, out] ctx     Signature context.
 * @param [in]      data    Data to append.
 * @param [in]      dataLen Length of data in bytes.
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_buf_append(wp_MlDsaSigCtx* ctx, const unsigned char* data,
    size_t dataLen)
{
    int ok = 1;
    size_t needed;
    unsigned char* tmp;

    needed = ctx->mdLen + dataLen;
    if (needed < ctx->mdLen) {
        ok = 0;
    }
    if (ok && (needed > ctx->mdCap)) {
        size_t newCap = ctx->mdCap == 0 ? 256 : ctx->mdCap;
        while (newCap < needed) {
            size_t doubled = newCap * 2;
            if (doubled < newCap) {
                ok = 0;
                break;
            }
            newCap = doubled;
        }
        if (ok) {
            tmp = (unsigned char*)OPENSSL_realloc(ctx->mdBuf, newCap);
            if (tmp == NULL) {
                ok = 0;
            }
            else {
                ctx->mdBuf = tmp;
                ctx->mdCap = newCap;
            }
        }
    }
    if (ok && (dataLen > 0)) {
        XMEMCPY(ctx->mdBuf + ctx->mdLen, data, dataLen);
        ctx->mdLen += dataLen;
    }
    return ok;
}

/**
 * Reset the streaming message buffer length to zero (keeps capacity).
 *
 * @param [in, out] ctx  Signature context.
 */
static void wp_mldsa_buf_reset(wp_MlDsaSigCtx* ctx)
{
    ctx->mdLen = 0;
}

/**
 * Create a new ML-DSA signature context object.
 *
 * @param [in] provCtx   Provider context.
 * @param [in] propq     Property query string. Unused.
 * @return  New signature context on success, NULL on failure.
 */
static wp_MlDsaSigCtx* wp_mldsa_newctx(WOLFPROV_CTX* provCtx, const char* propq)
{
    wp_MlDsaSigCtx* ctx = NULL;

    (void)propq;

    if (wolfssl_prov_is_running()) {
        ctx = (wp_MlDsaSigCtx*)OPENSSL_zalloc(sizeof(*ctx));
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
 * Free an ML-DSA signature context.
 *
 * @param [in, out] ctx  Signature context. May be NULL.
 */
static void wp_mldsa_freectx(wp_MlDsaSigCtx* ctx)
{
    if (ctx != NULL) {
        wc_FreeRng(&ctx->rng);
        wp_mldsa_free(ctx->mldsa);
        OPENSSL_clear_free(ctx->mdBuf, ctx->mdCap);
        OPENSSL_free(ctx);
    }
}

/**
 * Duplicate an ML-DSA signature context (key reference incremented).
 *
 * @param [in] srcCtx  Source signature context.
 * @return  New context on success, NULL on failure.
 */
static wp_MlDsaSigCtx* wp_mldsa_dupctx(wp_MlDsaSigCtx* srcCtx)
{
    wp_MlDsaSigCtx* dstCtx = NULL;

    if (!wolfssl_prov_is_running()) {
        return NULL;
    }

    dstCtx = wp_mldsa_newctx(srcCtx->provCtx, NULL);
    if (dstCtx == NULL) {
        return NULL;
    }
    if (srcCtx->mldsa != NULL) {
        if (!wp_mldsa_up_ref(srcCtx->mldsa)) {
            wp_mldsa_freectx(dstCtx);
            return NULL;
        }
        dstCtx->mldsa = srcCtx->mldsa;
    }
    if (srcCtx->mdLen > 0) {
        if (!wp_mldsa_buf_append(dstCtx, srcCtx->mdBuf, srcCtx->mdLen)) {
            wp_mldsa_freectx(dstCtx);
            return NULL;
        }
    }
    return dstCtx;
}

/**
 * Common init: take a reference on the key, reset state.
 *
 * @param [in, out] ctx     Signature context.
 * @param [in]      mldsa   ML-DSA key (reference taken).
 * @param [in]      params  Parameters. Unused.
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_init(wp_MlDsaSigCtx* ctx, wp_MlDsa* mldsa,
    const OSSL_PARAM params[])
{
    int ok = 1;

    (void)params;

    if ((ctx == NULL) || (mldsa == NULL)) {
        ok = 0;
    }
    if (ok && !wp_mldsa_up_ref(mldsa)) {
        ok = 0;
    }
    if (ok) {
        wp_mldsa_free(ctx->mldsa);
        ctx->mldsa = mldsa;
        wp_mldsa_buf_reset(ctx);
    }
    return ok;
}

static int wp_mldsa_sign_init(wp_MlDsaSigCtx* ctx, wp_MlDsa* mldsa,
    const OSSL_PARAM params[])
{
    return wp_mldsa_init(ctx, mldsa, params);
}

static int wp_mldsa_verify_init(wp_MlDsaSigCtx* ctx, wp_MlDsa* mldsa,
    const OSSL_PARAM params[])
{
    return wp_mldsa_init(ctx, mldsa, params);
}

/**
 * One-shot sign of a message.
 *
 * If sig is NULL, just report the signature size in sigLen.
 *
 * @param [in]      ctx       Signature context.
 * @param [out]     sig       Signature buffer.
 * @param [in, out] sigLen    On in, buffer size; on out, signature length.
 * @param [in]      sigSize   Allocated size of sig (unused).
 * @param [in]      msg       Message to sign.
 * @param [in]      msgLen    Message length.
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_sign(wp_MlDsaSigCtx* ctx, unsigned char* sig,
    size_t* sigLen, size_t sigSize, const unsigned char* msg, size_t msgLen)
{
    int ok = 1;
    int rc;
    word32 sigSz;

    (void)sigSize;

    if ((ctx == NULL) || (ctx->mldsa == NULL) || (sigLen == NULL)) {
        return 0;
    }

    sigSz = (word32)wp_mldsa_get_sig_size(ctx->mldsa);

    if (sig == NULL) {
        *sigLen = sigSz;
        return 1;
    }
    if (*sigLen < sigSz) {
        ok = 0;
    }
    if (ok) {
        word32 outLen = sigSz;
        rc = wc_dilithium_sign_msg(msg, (word32)msgLen, sig, &outLen,
            (MlDsaKey*)wp_mldsa_get_key(ctx->mldsa), &ctx->rng);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            *sigLen = outLen;
        }
    }
    return ok;
}

/**
 * One-shot verify of a signature on a message.
 *
 * @param [in] ctx     Signature context.
 * @param [in] sig     Signature.
 * @param [in] sigLen  Signature length.
 * @param [in] msg     Message.
 * @param [in] msgLen  Message length.
 * @return  1 if signature valid, 0 otherwise.
 */
static int wp_mldsa_verify(wp_MlDsaSigCtx* ctx, const unsigned char* sig,
    size_t sigLen, const unsigned char* msg, size_t msgLen)
{
    int ok = 1;
    int rc;
    int res = 0;

    if ((ctx == NULL) || (ctx->mldsa == NULL)) {
        return 0;
    }

    rc = wc_dilithium_verify_msg(sig, (word32)sigLen, msg, (word32)msgLen,
        &res, (MlDsaKey*)wp_mldsa_get_key(ctx->mldsa));
    if ((rc != 0) || (res != 1)) {
        ok = 0;
    }
    return ok;
}

/**
 * Digest-sign init: ML-DSA is pure (no pre-hash), so the buffer captures the
 * message and the one-shot signer is invoked at _final time.
 *
 * @param [in, out] ctx     Signature context.
 * @param [in]      mdName  Message digest name (must be NULL or empty).
 * @param [in]      mldsa   ML-DSA key (reference taken).
 * @param [in]      params  Parameters. Unused.
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_digest_sign_init(wp_MlDsaSigCtx* ctx, const char* mdName,
    wp_MlDsa* mldsa, const OSSL_PARAM params[])
{
    if ((mdName != NULL) && (mdName[0] != '\0')) {
        return 0;
    }
    return wp_mldsa_init(ctx, mldsa, params);
}

static int wp_mldsa_digest_verify_init(wp_MlDsaSigCtx* ctx, const char* mdName,
    wp_MlDsa* mldsa, const OSSL_PARAM params[])
{
    if ((mdName != NULL) && (mdName[0] != '\0')) {
        return 0;
    }
    return wp_mldsa_init(ctx, mldsa, params);
}

/**
 * Append data to the accumulated message buffer.
 *
 * @param [in, out] ctx      Signature context.
 * @param [in]      data     Data to append.
 * @param [in]      dataLen  Length of data.
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_digest_signverify_update(wp_MlDsaSigCtx* ctx,
    const unsigned char* data, size_t dataLen)
{
    if ((ctx == NULL) || (ctx->mldsa == NULL)) {
        return 0;
    }
    return wp_mldsa_buf_append(ctx, data, dataLen);
}

/**
 * Finalize a digest-style sign: produce signature over the buffered message.
 *
 * If sig is NULL, just report the signature size.
 *
 * @param [in]      ctx      Signature context.
 * @param [out]     sig      Signature buffer.
 * @param [in, out] sigLen   On in, buffer size; on out, signature length.
 * @param [in]      sigSize  Allocated size of sig (unused).
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_digest_sign_final(wp_MlDsaSigCtx* ctx, unsigned char* sig,
    size_t* sigLen, size_t sigSize)
{
    return wp_mldsa_sign(ctx, sig, sigLen, sigSize, ctx->mdBuf, ctx->mdLen);
}

/**
 * Finalize a digest-style verify on the buffered message.
 *
 * @param [in] ctx     Signature context.
 * @param [in] sig     Signature.
 * @param [in] sigLen  Signature length.
 * @return  1 if valid, 0 otherwise.
 */
static int wp_mldsa_digest_verify_final(wp_MlDsaSigCtx* ctx,
    const unsigned char* sig, size_t sigLen)
{
    return wp_mldsa_verify(ctx, sig, sigLen, ctx->mdBuf, ctx->mdLen);
}

/**
 * Get ctx params. None supported.
 */
static int wp_mldsa_get_ctx_params(wp_MlDsaSigCtx* ctx, OSSL_PARAM* params)
{
    (void)ctx;
    (void)params;
    return 1;
}

static const OSSL_PARAM* wp_mldsa_gettable_ctx_params(wp_MlDsaSigCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mldsa_gettable[] = {
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_mldsa_gettable;
}

/**
 * Set ctx params. None supported.
 */
static int wp_mldsa_set_ctx_params(wp_MlDsaSigCtx* ctx,
    const OSSL_PARAM params[])
{
    (void)ctx;
    (void)params;
    return 1;
}

static const OSSL_PARAM* wp_mldsa_settable_ctx_params(wp_MlDsaSigCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mldsa_settable[] = {
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_mldsa_settable;
}

/** Dispatch table for ML-DSA signatures (shared across all three levels). */
const OSSL_DISPATCH wp_mldsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,
        (DFUNC)wp_mldsa_newctx                                },
    { OSSL_FUNC_SIGNATURE_FREECTX,
        (DFUNC)wp_mldsa_freectx                               },
    { OSSL_FUNC_SIGNATURE_DUPCTX,
        (DFUNC)wp_mldsa_dupctx                                },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,
        (DFUNC)wp_mldsa_sign_init                             },
    { OSSL_FUNC_SIGNATURE_SIGN,
        (DFUNC)wp_mldsa_sign                                  },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        (DFUNC)wp_mldsa_verify_init                           },
    { OSSL_FUNC_SIGNATURE_VERIFY,
        (DFUNC)wp_mldsa_verify                                },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        (DFUNC)wp_mldsa_digest_sign_init                      },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        (DFUNC)wp_mldsa_digest_signverify_update              },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        (DFUNC)wp_mldsa_digest_sign_final                     },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        (DFUNC)wp_mldsa_digest_verify_init                    },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
        (DFUNC)wp_mldsa_digest_signverify_update              },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
        (DFUNC)wp_mldsa_digest_verify_final                   },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        (DFUNC)wp_mldsa_get_ctx_params                        },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        (DFUNC)wp_mldsa_gettable_ctx_params                   },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        (DFUNC)wp_mldsa_set_ctx_params                        },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        (DFUNC)wp_mldsa_settable_ctx_params                   },
    { 0, NULL }
};

#endif /* WP_HAVE_MLDSA */

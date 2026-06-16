/* wp_mldsa_sig.c
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
#include <wolfprovider/internal.h>

#ifdef WP_HAVE_MLDSA

#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/hash.h>

/**
 * ML-DSA signature context.
 *
 * ML-DSA is a pure signature (no streamed digest); digest_sign_* accumulates
 * the message in mdBuf and the one-shot signer is called in _final.
 */
/* FIPS 204 signing randomizer (rnd) and external-mu sizes, in bytes. */
#define WP_MLDSA_RND_SZ 32
#define WP_MLDSA_CTX_MAX 255

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
    /** FIPS 204 context string. */
    unsigned char context[WP_MLDSA_CTX_MAX];
    /** Length of context string. */
    size_t contextLen;
    /** Test-only signing randomizer (overrides deterministic/hedged). */
    unsigned char testEntropy[WP_MLDSA_RND_SZ];
    /** Length of test entropy (0 = not set). */
    size_t testEntropyLen;
    /** Deterministic signing (rnd = zeros) when set. */
    unsigned int deterministic;
    /** External-mu mode: the message IS the 64-byte mu. */
    unsigned int mu;
    /** Pre-hash (HashML-DSA) digest type, or WC_HASH_TYPE_NONE for pure. */
    enum wc_HashType hashType;
    /** Digest object updated with the message bytes in pre-hash mode. */
    wc_HashAlg hashObj;
} wp_MlDsaSigCtx;

static int wp_mldsa_set_ctx_params(wp_MlDsaSigCtx* ctx,
    const OSSL_PARAM params[]);


/**
 * Append data into the streaming message buffer.
 *
 * @param [in, out] ctx     Signature context.
 * @param [in]      data    Data to append.
 * @param [in]      dataLen Length of data in bytes.
 * @return  1 on success, 0 on failure.
 */
/* Upper bound on the accumulated message buffer (64 MiB). ML-DSA messages
 * are typically small (handshake transcripts, certificates); a cap prevents
 * a hostile caller from driving OOM via unbounded digest_sign_update. */
#define WP_MLDSA_BUF_MAX (64UL * 1024UL * 1024UL)

static int wp_mldsa_buf_append(wp_MlDsaSigCtx* ctx, const unsigned char* data,
    size_t dataLen)
{
    int ok = 1;
    size_t needed;
    size_t newCap;
    size_t doubled;
    unsigned char* tmp;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_buf_append");

    /* A NULL buffer with a non-zero length is a caller error; reject it before
     * the copy rather than dereferencing NULL. (NULL + 0 is a valid no-op.) */
    if ((data == NULL) && (dataLen != 0)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }

    needed = ctx->mdLen + dataLen;
    if (needed < ctx->mdLen) {
        ok = 0;
    }
    if (ok && (needed > WP_MLDSA_BUF_MAX)) {
        ok = 0;
    }
    if (ok && (needed > ctx->mdCap)) {
        newCap = ctx->mdCap == 0 ? 256 : ctx->mdCap;
        while (newCap < needed) {
            doubled = newCap * 2;
            if (doubled < newCap) {
                ok = 0;
                break;
            }
            newCap = doubled;
        }
        if (ok) {
            /* Grow by alloc+copy+zero rather than realloc so we always wipe
             * the previous block (message can be signer-confidential). */
            tmp = (unsigned char*)OPENSSL_malloc(newCap);
            if (tmp == NULL) {
                ok = 0;
            }
            if (ok) {
                if (ctx->mdLen > 0) {
                    XMEMCPY(tmp, ctx->mdBuf, ctx->mdLen);
                }
                OPENSSL_clear_free(ctx->mdBuf, ctx->mdCap);
                ctx->mdBuf = tmp;
                ctx->mdCap = newCap;
            }
        }
    }
    if (ok && (dataLen > 0)) {
        XMEMCPY(ctx->mdBuf + ctx->mdLen, data, dataLen);
        ctx->mdLen += dataLen;
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Reset the streaming message buffer length to zero (keeps capacity).
 *
 * @param [in, out] ctx  Signature context.
 */
static void wp_mldsa_buf_reset(wp_MlDsaSigCtx* ctx)
{
    /* Wipe stale bytes; ctx reuse across operations must not leak prior msg. */
    if ((ctx->mdBuf != NULL) && (ctx->mdLen > 0)) {
        wc_ForceZero(ctx->mdBuf, ctx->mdLen);
    }
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
        /* WC_HASH_TYPE_NONE is not guaranteed to be 0 (e.g. some FIPS enum
         * layouts), so set pure mode explicitly rather than relying on zalloc. */
        ctx->hashType = WC_HASH_TYPE_NONE;
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
        if (ctx->hashType != WC_HASH_TYPE_NONE) {
            wc_HashFree(&ctx->hashObj, ctx->hashType);
        }
        wp_mldsa_free(ctx->mldsa);
        OPENSSL_clear_free(ctx->mdBuf, ctx->mdCap);
        /* ctx embeds the signing-randomizer override (testEntropy); cleanse. */
        OPENSSL_clear_free(ctx, sizeof(*ctx));
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

    if ((!wolfssl_prov_is_running()) || (srcCtx == NULL)) {
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
    /* Carry the signature params so a dup'd context signs identically. */
    XMEMCPY(dstCtx->context, srcCtx->context, srcCtx->contextLen);
    dstCtx->contextLen = srcCtx->contextLen;
    XMEMCPY(dstCtx->testEntropy, srcCtx->testEntropy, srcCtx->testEntropyLen);
    dstCtx->testEntropyLen = srcCtx->testEntropyLen;
    dstCtx->deterministic = srcCtx->deterministic;
    dstCtx->mu = srcCtx->mu;
    /* Carry the in-progress pre-hash digest so the dup signs identically. */
    dstCtx->hashType = srcCtx->hashType;
    if ((srcCtx->hashType != WC_HASH_TYPE_NONE) &&
            (!wp_hash_copy(&srcCtx->hashObj, &dstCtx->hashObj
#if LIBWOLFSSL_VERSION_HEX < 0x05007004
                , srcCtx->hashType
#endif
                ))) {
        wp_mldsa_freectx(dstCtx);
        return NULL;
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
    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_init");

    if (ctx == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    /* NULL key means "reinit, reuse the key already on the context" -- only
     * valid if the context actually has one. */
    if ((mldsa == NULL) && (ctx->mldsa == NULL)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (mldsa != NULL) {
        if (!wp_mldsa_up_ref(mldsa)) {
            WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
            return 0;
        }
        wp_mldsa_free(ctx->mldsa);
        ctx->mldsa = mldsa;
    }
    wp_mldsa_buf_reset(ctx);
    if (ctx->hashType != WC_HASH_TYPE_NONE) {
        wc_HashFree(&ctx->hashObj, ctx->hashType);
        ctx->hashType = WC_HASH_TYPE_NONE;
    }
    /* Match OpenSSL: re-init clears external-mu but persists the context
     * string, deterministic flag and test-entropy until explicitly changed. */
    ctx->mu = 0;
    /* Apply the FIPS 204 signature params (context string, mu, message
     * encoding, deterministic, test-entropy) so every init path -- not just
     * the OpenSSL 3.5+ message API -- honors them. NULL params is a no-op. */
    if (!wp_mldsa_set_ctx_params(ctx, params)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

static int wp_mldsa_sign_init(wp_MlDsaSigCtx* ctx, wp_MlDsa* mldsa,
    const OSSL_PARAM params[])
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_sign_init");
    ok = wp_mldsa_init(ctx, mldsa, params);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static int wp_mldsa_verify_init(wp_MlDsaSigCtx* ctx, wp_MlDsa* mldsa,
    const OSSL_PARAM params[])
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_verify_init");
    ok = wp_mldsa_init(ctx, mldsa, params);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
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
/* Fill the 32-byte FIPS 204 signing randomizer: test entropy if supplied,
 * zeros when deterministic, otherwise random (hedged). */
static int wp_mldsa_fill_rnd(wp_MlDsaSigCtx* ctx, unsigned char* rnd)
{
    int rc = 0;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_fill_rnd");

    if (ctx->testEntropyLen == WP_MLDSA_RND_SZ) {
        XMEMCPY(rnd, ctx->testEntropy, WP_MLDSA_RND_SZ);
    }
    else if (ctx->deterministic) {
        XMEMSET(rnd, 0, WP_MLDSA_RND_SZ);
    }
    else {
        rc = wc_RNG_GenerateBlock(&ctx->rng, rnd, WP_MLDSA_RND_SZ);
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        rc == 0);
    return rc;
}

static int wp_mldsa_sign(wp_MlDsaSigCtx* ctx, unsigned char* sig,
    size_t* sigLen, size_t sigSize, const unsigned char* msg, size_t msgLen)
{
    int ok = 1;
    int rc;
    word32 sigSz;
    /* FIPS 204 permits an empty message; give wolfSSL a valid pointer so a
     * NULL+0 message does not become a backend-dependent NULL deref. */
    unsigned char dummy = 0;
    const unsigned char* m = msg;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_sign");

    if ((ctx == NULL) || (ctx->mldsa == NULL) || (sigLen == NULL)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if ((msg == NULL) && (msgLen != 0)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (m == NULL) {
        m = &dummy;
    }

    sigSz = (word32)wp_mldsa_get_sig_size(ctx->mldsa);

    if (sig == NULL) {
        *sigLen = sigSz;
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
        return 1;
    }
    /* sigSize is the authoritative buffer capacity; fall back to *sigLen only
     * when the dispatcher passes SIZE_MAX (matching wp_ecx_sig). */
    if (sigSize == (size_t)-1) {
        sigSize = *sigLen;
    }
    if (sigSize < sigSz) {
        ok = 0;
    }
    /* wolfSSL's ML-DSA API takes a 32-bit message length. Reject >4 GiB
     * messages explicitly rather than silently truncating. */
    if (ok && (msgLen > 0xFFFFFFFFU)) {
        ok = 0;
    }
    if (ok) {
        word32 outLen = sigSz;
        wc_MlDsaKey* key = (wc_MlDsaKey*)wp_mldsa_get_key(ctx->mldsa);
        unsigned char rnd[WP_MLDSA_RND_SZ];
        /* Supply a caller-controlled randomizer only when it is fixed (test
         * entropy or deterministic); otherwise let wolfSSL hedge it from its
         * own RNG rather than generating one here. */
        int useSeed = (ctx->testEntropyLen == WP_MLDSA_RND_SZ) ||
            ctx->deterministic;

        if (useSeed || ctx->mu) {
            if (wp_mldsa_fill_rnd(ctx, rnd) != 0) {
                ok = 0;
            }
        }
        if (ok && ctx->mu) {
            /* External-mu mode: only a seeded signer exists; the message is
             * the 64-byte mu. */
            rc = wc_MlDsaKey_SignMuWithSeed(key, sig, &outLen, m,
                (word32)msgLen, rnd);
            if (rc != 0) {
                ok = 0;
            }
        }
        else if (ok && useSeed) {
            /* FIPS 204 sec 5.2 pure ML-DSA, fixed randomizer. */
            rc = wc_MlDsaKey_SignCtxWithSeed(key, ctx->context,
                (byte)ctx->contextLen, sig, &outLen, m, (word32)msgLen, rnd);
            if (rc != 0) {
                ok = 0;
            }
        }
        else if (ok) {
            /* FIPS 204 sec 5.2 pure ML-DSA; wolfSSL generates the randomizer. */
            rc = wc_MlDsaKey_SignCtx(key, ctx->context, (byte)ctx->contextLen,
                sig, &outLen, m, (word32)msgLen, &ctx->rng);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            *sigLen = outLen;
        }
        /* The per-signature randomizer is sensitive; wipe it. */
        wc_ForceZero(rnd, sizeof(rnd));
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
    /* FIPS 204 permits an empty message; give wolfSSL a valid pointer. */
    unsigned char dummy = 0;
    const unsigned char* m = msg;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_verify");

    if ((ctx == NULL) || (ctx->mldsa == NULL) || (sig == NULL)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if ((msg == NULL) && (msgLen != 0)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (m == NULL) {
        m = &dummy;
    }
    /* wolfSSL's ML-DSA API takes 32-bit lengths. Reject oversize inputs
     * explicitly rather than silently truncating. */
    if ((sigLen > 0xFFFFFFFFU) || (msgLen > 0xFFFFFFFFU)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }

    /* Match the sign path: external-mu mode or pure ML-DSA with context. */
    if (ctx->mu) {
        rc = wc_MlDsaKey_VerifyMu(
            (wc_MlDsaKey*)wp_mldsa_get_key(ctx->mldsa), sig, (word32)sigLen,
            m, (word32)msgLen, &res);
    }
    else {
        rc = wc_MlDsaKey_VerifyCtx(
            (wc_MlDsaKey*)wp_mldsa_get_key(ctx->mldsa), sig, (word32)sigLen,
            ctx->context, (byte)ctx->contextLen, m, (word32)msgLen, &res);
    }
    if ((rc != 0) || (res != 1)) {
        ok = 0;
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/* Digests permitted for FIPS 204 HashML-DSA. Restricting to the SHA2/SHA3
 * families keeps the generic name mapper from admitting legacy/undersized
 * digests (MD5, SHA-1, SHA-512/224) as a HashML-DSA pre-hash. */
static int wp_mldsa_hash_allowed(enum wc_HashType hashType)
{
    int allowed = 0;

    if ((hashType == WC_HASH_TYPE_SHA256) ||
            (hashType == WC_HASH_TYPE_SHA384) ||
            (hashType == WC_HASH_TYPE_SHA512) ||
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) && \
    defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
            (hashType == WC_HASH_TYPE_SHA512_256) ||
#endif
            (hashType == WC_HASH_TYPE_SHA3_256) ||
            (hashType == WC_HASH_TYPE_SHA3_384) ||
            (hashType == WC_HASH_TYPE_SHA3_512)) {
        allowed = 1;
    }
    return allowed;
}

/* Select a pre-hash (HashML-DSA) digest from the supplied name and start the
 * digest object that the update path feeds. Leaves the context in pure mode
 * (hashType WC_HASH_TYPE_NONE) when no digest name is given. */
static int wp_mldsa_setup_prehash(wp_MlDsaSigCtx* ctx, const char* mdName)
{
    int ok = 1;
    int rc;
    OSSL_LIB_CTX* libCtx = (ctx->provCtx != NULL) ? ctx->provCtx->libCtx : NULL;

    ctx->hashType = wp_name_to_wc_hash_type(libCtx, mdName, NULL);
    if (!wp_mldsa_hash_allowed(ctx->hashType)) {
        ctx->hashType = WC_HASH_TYPE_NONE;
        ok = 0;
    }
    if (ok) {
        rc = wc_HashInit_ex(&ctx->hashObj, ctx->hashType, NULL, INVALID_DEVID);
        if (rc != 0) {
            ctx->hashType = WC_HASH_TYPE_NONE;
            ok = 0;
        }
    }
    return ok;
}

/* FIPS 204 sec 5.4.1 HashML-DSA: sign the pre-hash digest with the supplied
 * context. wolfSSL generates the randomizer unless one is fixed (test entropy
 * or deterministic), in which case the seeded API is used. */
static int wp_mldsa_sign_prehash(wp_MlDsaSigCtx* ctx, unsigned char* sig,
    size_t* sigLen, size_t sigSize)
{
    int ok = 1;
    int rc;
    word32 sigSz;
    int digestLen;
    unsigned char digest[WC_MAX_DIGEST_SIZE];

    if ((ctx->mldsa == NULL) || (sigLen == NULL)) {
        return 0;
    }
    sigSz = (word32)wp_mldsa_get_sig_size(ctx->mldsa);
    if (sig == NULL) {
        *sigLen = sigSz;
        return 1;
    }
    if (sigSize == (size_t)-1) {
        sigSize = *sigLen;
    }
    if (sigSize < sigSz) {
        ok = 0;
    }
    digestLen = wc_HashGetDigestSize(ctx->hashType);
    if (ok && (digestLen <= 0)) {
        ok = 0;
    }
    if (ok && (wc_HashFinal(&ctx->hashObj, ctx->hashType, digest) != 0)) {
        ok = 0;
    }
    if (ok) {
        word32 outLen = sigSz;
        wc_MlDsaKey* key = (wc_MlDsaKey*)wp_mldsa_get_key(ctx->mldsa);
        unsigned char rnd[WP_MLDSA_RND_SZ];
        int useSeed = (ctx->testEntropyLen == WP_MLDSA_RND_SZ) ||
            ctx->deterministic;

        if (useSeed) {
            if (wp_mldsa_fill_rnd(ctx, rnd) != 0) {
                ok = 0;
            }
            if (ok) {
                rc = wc_MlDsaKey_SignCtxHashWithSeed(key, ctx->context,
                    (byte)ctx->contextLen, sig, &outLen, digest,
                    (word32)digestLen, (int)ctx->hashType, rnd);
                if (rc != 0) {
                    ok = 0;
                }
            }
        }
        else {
            rc = wc_MlDsaKey_SignCtxHash(key, ctx->context,
                (byte)ctx->contextLen, sig, &outLen, digest,
                (word32)digestLen, (int)ctx->hashType, &ctx->rng);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            *sigLen = outLen;
        }
        wc_ForceZero(rnd, sizeof(rnd));
    }
    return ok;
}

/* FIPS 204 sec 5.4.1 HashML-DSA verify of a pre-hash digest. */
static int wp_mldsa_verify_prehash(wp_MlDsaSigCtx* ctx,
    const unsigned char* sig, size_t sigLen)
{
    int ok = 1;
    int res = 0;
    int digestLen;
    unsigned char digest[WC_MAX_DIGEST_SIZE];

    if (sigLen > 0xFFFFFFFFU) {
        return 0;
    }
    digestLen = wc_HashGetDigestSize(ctx->hashType);
    if (digestLen <= 0) {
        ok = 0;
    }
    if (ok && (wc_HashFinal(&ctx->hashObj, ctx->hashType, digest) != 0)) {
        ok = 0;
    }
    if (ok) {
        int rc = wc_MlDsaKey_VerifyCtxHash(
            (wc_MlDsaKey*)wp_mldsa_get_key(ctx->mldsa), sig, (word32)sigLen,
            ctx->context, (byte)ctx->contextLen, digest, (word32)digestLen,
            (int)ctx->hashType, &res);
        if ((rc != 0) || (res != 1)) {
            ok = 0;
        }
    }
    return ok;
}

/**
 * Digest-sign init. With no digest name ML-DSA is pure: the buffer captures
 * the message and the one-shot signer runs at _final. With a digest name the
 * pre-hash (HashML-DSA) path streams the message into a digest object.
 *
 * @param [in, out] ctx     Signature context.
 * @param [in]      mdName  Message digest name, or NULL/empty for pure ML-DSA.
 * @param [in]      mldsa   ML-DSA key (reference taken).
 * @param [in]      params  Parameters. Unused.
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_digest_sign_init(wp_MlDsaSigCtx* ctx, const char* mdName,
    wp_MlDsa* mldsa, const OSSL_PARAM params[])
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_digest_sign_init");
    ok = wp_mldsa_init(ctx, mldsa, params);
    if (ok && (mdName != NULL) && (mdName[0] != '\0')) {
        /* External-mu and pre-hash (HashML-DSA) are mutually exclusive. */
        if (ctx->mu) {
            ok = 0;
        }
        else {
            ok = wp_mldsa_setup_prehash(ctx, mdName);
        }
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static int wp_mldsa_digest_verify_init(wp_MlDsaSigCtx* ctx, const char* mdName,
    wp_MlDsa* mldsa, const OSSL_PARAM params[])
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_digest_verify_init");
    ok = wp_mldsa_init(ctx, mldsa, params);
    if (ok && (mdName != NULL) && (mdName[0] != '\0')) {
        /* External-mu and pre-hash (HashML-DSA) are mutually exclusive. */
        if (ctx->mu) {
            ok = 0;
        }
        else {
            ok = wp_mldsa_setup_prehash(ctx, mdName);
        }
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Update the in-progress signature. Pre-hash mode feeds the digest object;
 * pure mode accumulates the raw message.
 *
 * @param [in, out] ctx      Signature context.
 * @param [in]      data     Data to append.
 * @param [in]      dataLen  Length of data.
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_digest_signverify_update(wp_MlDsaSigCtx* ctx,
    const unsigned char* data, size_t dataLen)
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_digest_signverify_update");
    if ((ctx == NULL) || (ctx->mldsa == NULL)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if ((data == NULL) && (dataLen != 0)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (ctx->hashType != WC_HASH_TYPE_NONE) {
        if (dataLen > 0xFFFFFFFFU) {
            ok = 0;
        }
        else {
            ok = (wc_HashUpdate(&ctx->hashObj, ctx->hashType, data,
                (word32)dataLen) == 0);
        }
    }
    else {
        ok = wp_mldsa_buf_append(ctx, data, dataLen);
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize a digest-style sign. If sig is NULL, just report the signature
 * size.
 *
 * @param [in]      ctx      Signature context.
 * @param [out]     sig      Signature buffer.
 * @param [in, out] sigLen   On in, buffer size; on out, signature length.
 * @param [in]      sigSize  Allocated size of sig.
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_digest_sign_final(wp_MlDsaSigCtx* ctx, unsigned char* sig,
    size_t* sigLen, size_t sigSize)
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_digest_sign_final");
    if (ctx == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (ctx->hashType != WC_HASH_TYPE_NONE) {
        ok = wp_mldsa_sign_prehash(ctx, sig, sigLen, sigSize);
    }
    else {
        ok = wp_mldsa_sign(ctx, sig, sigLen, sigSize, ctx->mdBuf, ctx->mdLen);
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize a digest-style verify.
 *
 * @param [in] ctx     Signature context.
 * @param [in] sig     Signature.
 * @param [in] sigLen  Signature length.
 * @return  1 if valid, 0 otherwise.
 */
static int wp_mldsa_digest_verify_final(wp_MlDsaSigCtx* ctx,
    const unsigned char* sig, size_t sigLen)
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_digest_verify_final");
    if (ctx == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (ctx->hashType != WC_HASH_TYPE_NONE) {
        ok = wp_mldsa_verify_prehash(ctx, sig, sigLen);
    }
    else {
        ok = wp_mldsa_verify(ctx, sig, sigLen, ctx->mdBuf, ctx->mdLen);
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/* OpenSSL 3.5+ ML-DSA signature message API. The init carries the FIPS 204
 * signature params (context, deterministic, mu, test-entropy); wp_mldsa_init
 * applies them. update/final reuse the digest-sign message accumulation. */
static int wp_mldsa_message_init(wp_MlDsaSigCtx* ctx, wp_MlDsa* mldsa,
    const OSSL_PARAM params[])
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_message_init");

    ok = wp_mldsa_init(ctx, mldsa, params);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static int wp_mldsa_sign_message_final(wp_MlDsaSigCtx* ctx, unsigned char* sig,
    size_t* sigLen, size_t sigSize)
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_sign_message_final");
    if (ctx == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    ok = wp_mldsa_sign(ctx, sig, sigLen, sigSize, ctx->mdBuf, ctx->mdLen);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static int wp_mldsa_verify_message_final(wp_MlDsaSigCtx* ctx,
    const unsigned char* sig, size_t sigLen)
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_verify_message_final");
    if (ctx == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    ok = wp_mldsa_verify(ctx, sig, sigLen, ctx->mdBuf, ctx->mdLen);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/* DER AlgorithmIdentifier (SEQUENCE { OID }) for each ML-DSA level. ML-DSA
 * signature algorithms carry no parameters, so the encoding is a fixed
 * 13-byte sequence differing only in the final OID arc (17/18/19). */
static const byte wp_mldsa44_aid[] = {
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x11
};
static const byte wp_mldsa65_aid[] = {
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x12
};
static const byte wp_mldsa87_aid[] = {
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x13
};

/* Set the X.509 signature AlgorithmIdentifier for the key's ML-DSA level. */
static int wp_mldsa_get_alg_id(wp_MlDsaSigCtx* ctx, OSSL_PARAM* p)
{
    int ok = 1;
    int level = wp_mldsa_get_level(ctx->mldsa);
    const byte* aid = NULL;
    size_t aidLen = 0;

    if (level == WC_ML_DSA_44) {
        aid = wp_mldsa44_aid;
        aidLen = sizeof(wp_mldsa44_aid);
    }
    else if (level == WC_ML_DSA_65) {
        aid = wp_mldsa65_aid;
        aidLen = sizeof(wp_mldsa65_aid);
    }
    else if (level == WC_ML_DSA_87) {
        aid = wp_mldsa87_aid;
        aidLen = sizeof(wp_mldsa87_aid);
    }
    else {
        ok = 0;
    }
    if (ok && !OSSL_PARAM_set_octet_string(p, aid, aidLen)) {
        ok = 0;
    }
    return ok;
}

/* Provides the X.509 signature AlgorithmIdentifier so certificate and other
 * structure signing (ASN1_item_sign_ctx) can build the signatureAlgorithm. */
static int wp_mldsa_get_ctx_params(wp_MlDsaSigCtx* ctx, OSSL_PARAM* params)
{
    int ok = 1;
    OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_get_ctx_params");

    if (ctx == NULL) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL) {
            ok = wp_mldsa_get_alg_id(ctx, p);
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static const OSSL_PARAM* wp_mldsa_gettable_ctx_params(wp_MlDsaSigCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mldsa_gettable[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_mldsa_gettable;
}

/* Honor the FIPS 204 signature params OpenSSL drives ML-DSA with: context
 * string, deterministic/hedged selection, external-mu, and a test-only
 * randomizer. message-encoding must be pure (1); raw is unsupported. */
static int wp_mldsa_set_ctx_params(wp_MlDsaSigCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_set_ctx_params");

    if (ctx == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (params == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
        return 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p != NULL) {
        void* vp = ctx->context;
        ctx->contextLen = 0;
        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(ctx->context),
                &ctx->contextLen)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC);
        if ((p != NULL) && !OSSL_PARAM_get_uint(p, &ctx->deterministic)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MU);
        if ((p != NULL) && !OSSL_PARAM_get_uint(p, &ctx->mu)) {
            ok = 0;
        }
        /* External-mu and pre-hash (HashML-DSA) are mutually exclusive. */
        if (ok && ctx->mu && (ctx->hashType != WC_HASH_TYPE_NONE)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params,
            OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING);
        if (p != NULL) {
            unsigned int enc = 1;
            /* Only FIPS 204 pure encoding (1) is supported. */
            if (!OSSL_PARAM_get_uint(p, &enc) || (enc != 1)) {
                ok = 0;
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY);
        if (p != NULL) {
            void* vp = ctx->testEntropy;
            ctx->testEntropyLen = 0;
            if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(ctx->testEntropy),
                    &ctx->testEntropyLen)) {
                ok = 0;
            }
            /* A short randomizer would be silently ignored; require the exact
             * FIPS 204 size. */
            else if (ctx->testEntropyLen != WP_MLDSA_RND_SZ) {
                ctx->testEntropyLen = 0;
                ok = 0;
            }
        }
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static const OSSL_PARAM* wp_mldsa_settable_ctx_params(wp_MlDsaSigCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mldsa_settable[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_DETERMINISTIC, NULL),
        OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_MU, NULL),
        OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, NULL),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, NULL, 0),
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
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
        (DFUNC)wp_mldsa_message_init                          },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,
        (DFUNC)wp_mldsa_digest_signverify_update              },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,
        (DFUNC)wp_mldsa_sign_message_final                    },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
        (DFUNC)wp_mldsa_message_init                          },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
        (DFUNC)wp_mldsa_digest_signverify_update              },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,
        (DFUNC)wp_mldsa_verify_message_final                  },
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

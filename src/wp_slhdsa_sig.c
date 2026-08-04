/* wp_slhdsa_sig.c
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

#ifdef WP_HAVE_SLHDSA

#include <wolfssl/wolfcrypt/wc_slhdsa.h>

/* FIPS 205 context string limit and the largest additional-randomness (n). */
#define WP_SLHDSA_CTX_MAX 255
#define WP_SLHDSA_RND_MAX 32

/* wolfSSL has no SLH-DSA streaming API, so bound the buffered message. */
#define WP_SLHDSA_BUF_MAX (64UL * 1024UL * 1024UL)

/* SLH-DSA signature context. */
typedef struct wp_SlhDsaSigCtx {
    WOLFPROV_CTX* provCtx;
    wp_SlhDsa* slhdsa;
#ifdef WP_HAVE_SLHDSA_PRIVATE
    WC_RNG rng;
#endif
    unsigned char* mdBuf;
    size_t mdLen;
    size_t mdCap;
    unsigned char* verifySig;
    size_t verifySigLen;
    unsigned char context[WP_SLHDSA_CTX_MAX];
    size_t contextLen;
    unsigned char testEntropy[WP_SLHDSA_RND_MAX];
    size_t testEntropyLen;
    unsigned int deterministic; /* Deterministic signing. */
    unsigned int rawMsg;        /* Message is already FIPS 205 M'. */
} wp_SlhDsaSigCtx;

static int wp_slhdsa_set_ctx_params(wp_SlhDsaSigCtx* ctx,
    const OSSL_PARAM params[]);


/**
 * Append data into the streaming message buffer.
 *
 * @param [in, out] ctx      Signature context.
 * @param [in]      data     Data to append.
 * @param [in]      dataLen  Length of data in bytes.
 * @return  1 on success, 0 on failure.
 */
static int wp_slhdsa_buf_append(wp_SlhDsaSigCtx* ctx,
    const unsigned char* data, size_t dataLen)
{
    int ok = 1;
    size_t needed;
    size_t newCap;
    size_t doubled;
    unsigned char* tmp;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_buf_append");

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
    if (ok && (needed > WP_SLHDSA_BUF_MAX)) {
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
static void wp_slhdsa_buf_reset(wp_SlhDsaSigCtx* ctx)
{
    /* Wipe stale bytes; ctx reuse across operations must not leak prior msg. */
    if ((ctx->mdBuf != NULL) && (ctx->mdLen > 0)) {
        wc_ForceZero(ctx->mdBuf, ctx->mdLen);
    }
    ctx->mdLen = 0;
}

/**
 * Create a new SLH-DSA signature context object.
 *
 * @param [in] provCtx  Provider context.
 * @param [in] propq    Property query string. Unused.
 * @return  New signature context on success, NULL on failure.
 */
static wp_SlhDsaSigCtx* wp_slhdsa_newctx(WOLFPROV_CTX* provCtx,
    const char* propq)
{
    wp_SlhDsaSigCtx* ctx = NULL;

    (void)propq;

    if (wolfssl_prov_is_running()) {
        ctx = (wp_SlhDsaSigCtx*)OPENSSL_zalloc(sizeof(*ctx));
    }
#ifdef WP_HAVE_SLHDSA_PRIVATE
    if (ctx != NULL) {
        int rc = wc_InitRng(&ctx->rng);
        if (rc != 0) {
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }
#endif
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }
    return ctx;
}

/**
 * Free an SLH-DSA signature context.
 *
 * @param [in, out] ctx  Signature context. May be NULL.
 */
static void wp_slhdsa_freectx(wp_SlhDsaSigCtx* ctx)
{
    if (ctx != NULL) {
#ifdef WP_HAVE_SLHDSA_PRIVATE
        wc_FreeRng(&ctx->rng);
#endif
        wp_slhdsa_free(ctx->slhdsa);
        OPENSSL_clear_free(ctx->mdBuf, ctx->mdCap);
        OPENSSL_free(ctx->verifySig);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

/**
 * Duplicate an SLH-DSA signature context.
 *
 * @param [in] src  Source signature context.
 * @return  New signature context on success, NULL on failure.
 */
static wp_SlhDsaSigCtx* wp_slhdsa_dupctx(wp_SlhDsaSigCtx* src)
{
    wp_SlhDsaSigCtx* dst = NULL;
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_dupctx");

    if (!wolfssl_prov_is_running() || (src == NULL)) {
        ok = 0;
    }
    if (ok) {
        dst = wp_slhdsa_newctx(src->provCtx, NULL);
        if (dst == NULL) {
            ok = 0;
        }
    }
    if (ok && (src->slhdsa != NULL) && !wp_slhdsa_up_ref(src->slhdsa)) {
        ok = 0;
    }
    if (ok) {
        dst->slhdsa = src->slhdsa;
        if (src->mdLen > 0) {
            ok = wp_slhdsa_buf_append(dst, src->mdBuf, src->mdLen);
        }
    }
    if (ok) {
        XMEMCPY(dst->context, src->context, src->contextLen);
        dst->contextLen = src->contextLen;
        XMEMCPY(dst->testEntropy, src->testEntropy, src->testEntropyLen);
        dst->testEntropyLen = src->testEntropyLen;
        dst->deterministic = src->deterministic;
        dst->rawMsg = src->rawMsg;
    }
    if (ok && (src->verifySig != NULL)) {
        dst->verifySig = OPENSSL_memdup(src->verifySig, src->verifySigLen);
        if (dst->verifySig == NULL) {
            ok = 0;
        }
        else {
            dst->verifySigLen = src->verifySigLen;
        }
    }
    if (!ok) {
        wp_slhdsa_freectx(dst);
        dst = NULL;
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        dst != NULL);
    return dst;
}

/**
 * Common init: take a reference on the key, reset state.
 *
 * @param [in, out] ctx     Signature context.
 * @param [in]      slhdsa  SLH-DSA key (reference taken).
 * @param [in]      params  Parameters to apply.
 * @return  1 on success, 0 on failure.
 */
static int wp_slhdsa_init(wp_SlhDsaSigCtx* ctx, wp_SlhDsa* slhdsa,
    const OSSL_PARAM params[])
{
    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_init");

    if (ctx == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    /* NULL reuses the existing key and requires one to be present. */
    if ((slhdsa == NULL) && (ctx->slhdsa == NULL)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (slhdsa != NULL) {
        if (!wp_slhdsa_up_ref(slhdsa)) {
            WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
            return 0;
        }
        wp_slhdsa_free(ctx->slhdsa);
        ctx->slhdsa = slhdsa;
    }
    wp_slhdsa_buf_reset(ctx);
    OPENSSL_free(ctx->verifySig);
    ctx->verifySig = NULL;
    ctx->verifySigLen = 0;
    /* Match OpenSSL: the context string, deterministic mode, test entropy and
     * message encoding persist across re-init until explicitly changed. */
    if (!wp_slhdsa_set_ctx_params(ctx, params)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

#ifdef WP_HAVE_SLHDSA_PRIVATE
static int wp_slhdsa_sign_init(wp_SlhDsaSigCtx* ctx, wp_SlhDsa* slhdsa,
    const OSSL_PARAM params[])
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_sign_init");
    ok = wp_slhdsa_init(ctx, slhdsa, params);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif

static int wp_slhdsa_verify_init(wp_SlhDsaSigCtx* ctx, wp_SlhDsa* slhdsa,
    const OSSL_PARAM params[])
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_verify_init");
    ok = wp_slhdsa_init(ctx, slhdsa, params);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#ifdef WP_HAVE_SLHDSA_PRIVATE
/**
 * One-shot sign of a message.
 *
 * If sig is NULL, just report the signature size in sigLen.
 *
 * @param [in]      ctx      Signature context.
 * @param [out]     sig      Signature buffer.
 * @param [in, out] sigLen   On in, buffer size; on out, signature length.
 * @param [in]      sigSize  Allocated size of sig.
 * @param [in]      msg      Message to sign.
 * @param [in]      msgLen   Message length.
 * @return  1 on success, 0 on failure.
 */
static int wp_slhdsa_sign(wp_SlhDsaSigCtx* ctx, unsigned char* sig,
    size_t* sigLen, size_t sigSize, const unsigned char* msg, size_t msgLen)
{
    int ok = 1;
    int rc = -1;
    int locked = 0;
    word32 sigSz;
    /* FIPS 205 permits an empty message; give wolfSSL a valid pointer so a
     * NULL+0 message does not become a backend-dependent NULL deref. */
    unsigned char dummy = 0;
    const unsigned char* m = msg;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_sign");

    if ((ctx == NULL) || (ctx->slhdsa == NULL) || (sigLen == NULL)) {
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

    sigSz = (word32)wp_slhdsa_get_sig_size(ctx->slhdsa);

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
    /* wolfSSL's SLH-DSA API takes a 32-bit message length. Reject >4 GiB
     * messages explicitly rather than silently truncating. */
    if (ok && (!WP_FITS_WORD32(msgLen))) {
        ok = 0;
    }
    /* Test entropy is sized against the key it was set for, and a re-init can
     * swap in a key from another parameter set. wolfSSL reads n bytes, so a
     * stale value would pad the randomizer with zeros the caller never gave. */
    if (ok && (ctx->testEntropyLen > 0) &&
            (ctx->testEntropyLen != (size_t)wp_slhdsa_get_n(ctx->slhdsa))) {
        ok = 0;
    }
    if (ok) {
        word32 outLen = sigSz;
        SlhDsaKey* key = (SlhDsaKey*)wp_slhdsa_get_key(ctx->slhdsa);

        if (wp_lock(wp_slhdsa_get_mutex(ctx->slhdsa)) != 1) {
            ok = 0;
        }
        else {
            locked = 1;
        }
        if (ok && ctx->rawMsg) {
            /* FIPS 205 internal interface: the message already is M', so the
             * context string is part of it and must not be applied again. */
            if (ctx->testEntropyLen > 0) {
                rc = wc_SlhDsaKey_SignMsgWithRandom(key, m, (word32)msgLen,
                    sig, &outLen, ctx->testEntropy);
            }
            else if (ctx->deterministic) {
                rc = wc_SlhDsaKey_SignMsgDeterministic(key, m, (word32)msgLen,
                    sig, &outLen);
            }
            else {
                byte rnd[WP_SLHDSA_RND_MAX];
                int n = wp_slhdsa_get_n(ctx->slhdsa);

                rc = wc_RNG_GenerateBlock(&ctx->rng, rnd, (word32)n);
                if (rc == 0) {
                    rc = wc_SlhDsaKey_SignMsgWithRandom(key, m,
                        (word32)msgLen, sig, &outLen, rnd);
                }
                wc_ForceZero(rnd, sizeof(rnd));
            }
        }
        else if (ok && (ctx->testEntropyLen > 0)) {
            rc = wc_SlhDsaKey_SignWithRandom(key, ctx->context,
                (byte)ctx->contextLen, m, (word32)msgLen, sig, &outLen,
                ctx->testEntropy);
        }
        else if (ok && ctx->deterministic) {
            rc = wc_SlhDsaKey_SignDeterministic(key, ctx->context,
                (byte)ctx->contextLen, m, (word32)msgLen, sig, &outLen);
        }
        else if (ok) {
            rc = wc_SlhDsaKey_Sign(key, ctx->context, (byte)ctx->contextLen,
                m, (word32)msgLen, sig, &outLen, &ctx->rng);
        }
        if (locked) {
            wp_unlock(wp_slhdsa_get_mutex(ctx->slhdsa));
        }
        if (ok && (rc != 0)) {
            ok = 0;
        }
        if (ok) {
            *sigLen = outLen;
        }
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif /* WP_HAVE_SLHDSA_PRIVATE */

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
static int wp_slhdsa_verify(wp_SlhDsaSigCtx* ctx, const unsigned char* sig,
    size_t sigLen, const unsigned char* msg, size_t msgLen)
{
    int ok = 1;
    int rc = -1;
    int locked = 0;
    /* FIPS 205 permits an empty message; give wolfSSL a valid pointer. */
    unsigned char dummy = 0;
    const unsigned char* m = msg;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_verify");

    if ((ctx == NULL) || (ctx->slhdsa == NULL) || (sig == NULL)) {
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
    /* wolfSSL's SLH-DSA API takes 32-bit lengths. Reject oversize inputs
     * explicitly rather than silently truncating. */
    if ((!WP_FITS_WORD32(sigLen)) || (!WP_FITS_WORD32(msgLen))) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }

    /* Returns 0 only for a valid signature; SIG_VERIFY_E and every other
     * non-zero code is a verification failure. */
    if (wp_lock(wp_slhdsa_get_mutex(ctx->slhdsa)) != 1) {
        ok = 0;
    }
    else {
        locked = 1;
    }
    if (ok && ctx->rawMsg) {
        rc = wc_SlhDsaKey_VerifyMsg((SlhDsaKey*)wp_slhdsa_get_key(ctx->slhdsa),
            m, (word32)msgLen, sig, (word32)sigLen);
    }
    else if (ok) {
        rc = wc_SlhDsaKey_Verify((SlhDsaKey*)wp_slhdsa_get_key(ctx->slhdsa),
            ctx->context, (byte)ctx->contextLen, m, (word32)msgLen, sig,
            (word32)sigLen);
    }
    if (locked) {
        wp_unlock(wp_slhdsa_get_mutex(ctx->slhdsa));
    }
    if (ok && (rc != 0)) {
        ok = 0;
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Reject a pre-hash digest name. FIPS 205 HashSLH-DSA is a distinct algorithm
 * and is not implemented here, so a named digest must not be silently ignored.
 *
 * @param [in] mdName  Digest name, may be NULL or empty for pure mode.
 * @return  1 when pure mode, 0 when a digest was requested.
 */
static int wp_slhdsa_check_pure(const char* mdName)
{
    return (mdName == NULL) || (mdName[0] == '\0');
}

#ifdef WP_HAVE_SLHDSA_PRIVATE
static int wp_slhdsa_digest_sign_init(wp_SlhDsaSigCtx* ctx, const char* mdName,
    wp_SlhDsa* slhdsa, const OSSL_PARAM params[])
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_digest_sign_init");
    ok = wp_slhdsa_check_pure(mdName) && wp_slhdsa_init(ctx, slhdsa, params);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif

static int wp_slhdsa_digest_verify_init(wp_SlhDsaSigCtx* ctx,
    const char* mdName, wp_SlhDsa* slhdsa, const OSSL_PARAM params[])
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_digest_verify_init");
    ok = wp_slhdsa_check_pure(mdName) && wp_slhdsa_init(ctx, slhdsa, params);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Accumulate message bytes for a streamed sign or verify.
 *
 * @param [in, out] ctx      Signature context.
 * @param [in]      data     Data to append.
 * @param [in]      dataLen  Length of data.
 * @return  1 on success, 0 on failure.
 */
static int wp_slhdsa_digest_signverify_update(wp_SlhDsaSigCtx* ctx,
    const unsigned char* data, size_t dataLen)
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_digest_signverify_update");
    if ((ctx == NULL) || (ctx->slhdsa == NULL)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    ok = wp_slhdsa_buf_append(ctx, data, dataLen);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#ifdef WP_HAVE_SLHDSA_PRIVATE
static int wp_slhdsa_digest_sign_final(wp_SlhDsaSigCtx* ctx,
    unsigned char* sig, size_t* sigLen, size_t sigSize)
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_digest_sign_final");
    if (ctx == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    ok = wp_slhdsa_sign(ctx, sig, sigLen, sigSize, ctx->mdBuf, ctx->mdLen);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif

static int wp_slhdsa_digest_verify_final(wp_SlhDsaSigCtx* ctx,
    const unsigned char* sig, size_t sigLen)
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_digest_verify_final");
    if (ctx == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    ok = wp_slhdsa_verify(ctx, sig, sigLen, ctx->mdBuf, ctx->mdLen);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/* OpenSSL 3.5+ signature message API. */
static int wp_slhdsa_message_init(wp_SlhDsaSigCtx* ctx, wp_SlhDsa* slhdsa,
    const OSSL_PARAM params[])
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_message_init");
    ok = wp_slhdsa_init(ctx, slhdsa, params);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#ifdef WP_HAVE_SLHDSA_PRIVATE
static int wp_slhdsa_sign_message_final(wp_SlhDsaSigCtx* ctx,
    unsigned char* sig, size_t* sigLen, size_t sigSize)
{
    return wp_slhdsa_digest_sign_final(ctx, sig, sigLen, sigSize);
}
#endif

static int wp_slhdsa_verify_message_init(wp_SlhDsaSigCtx* ctx,
    wp_SlhDsa* slhdsa, const OSSL_PARAM params[])
{
    return wp_slhdsa_message_init(ctx, slhdsa, params);
}

static int wp_slhdsa_verify_message_final(wp_SlhDsaSigCtx* ctx)
{
    if ((ctx == NULL) || (ctx->verifySig == NULL)) {
        return 0;
    }
    return wp_slhdsa_digest_verify_final(ctx, ctx->verifySig,
        ctx->verifySigLen);
}

/* DER AlgorithmIdentifier (SEQUENCE { OID }) for each SLH-DSA parameter set.
 * FIPS 205 signature algorithms carry no parameters, so the encoding differs
 * only in the final OID arc (20 through 31). */
static const byte wp_slhdsa_aid_prefix[] = {
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03
};

/* Map a parameter id to its OID arc, following the id-slh-dsa-* assignment
 * order: SHA2 128s..256f are .20-.25, SHAKE 128s..256f are .26-.31. */
static int wp_slhdsa_aid_arc(int param, byte* arc)
{
    int ok = 1;

    switch (param) {
        case SLHDSA_SHAKE128S: *arc = 0x1a; break;
        case SLHDSA_SHAKE128F: *arc = 0x1b; break;
        case SLHDSA_SHAKE192S: *arc = 0x1c; break;
        case SLHDSA_SHAKE192F: *arc = 0x1d; break;
        case SLHDSA_SHAKE256S: *arc = 0x1e; break;
        case SLHDSA_SHAKE256F: *arc = 0x1f; break;
    #ifdef WOLFSSL_SLHDSA_SHA2
        case SLHDSA_SHA2_128S: *arc = 0x14; break;
        case SLHDSA_SHA2_128F: *arc = 0x15; break;
        case SLHDSA_SHA2_192S: *arc = 0x16; break;
        case SLHDSA_SHA2_192F: *arc = 0x17; break;
        case SLHDSA_SHA2_256S: *arc = 0x18; break;
        case SLHDSA_SHA2_256F: *arc = 0x19; break;
    #endif
        default:
            ok = 0;
            break;
    }
    return ok;
}

/* Set the X.509 signature AlgorithmIdentifier for the key's parameter set. */
static int wp_slhdsa_get_alg_id(wp_SlhDsaSigCtx* ctx, OSSL_PARAM* p)
{
    int ok = 1;
    byte aid[sizeof(wp_slhdsa_aid_prefix) + 1];
    byte arc = 0;

    if (!wp_slhdsa_aid_arc(wp_slhdsa_get_param(ctx->slhdsa), &arc)) {
        ok = 0;
    }
    if (ok) {
        XMEMCPY(aid, wp_slhdsa_aid_prefix, sizeof(wp_slhdsa_aid_prefix));
        aid[sizeof(wp_slhdsa_aid_prefix)] = arc;
        if (!OSSL_PARAM_set_octet_string(p, aid, sizeof(aid))) {
            ok = 0;
        }
    }
    return ok;
}

/* Provides the X.509 signature AlgorithmIdentifier so certificate and other
 * structure signing (ASN1_item_sign_ctx) can build the signatureAlgorithm. */
static int wp_slhdsa_get_ctx_params(wp_SlhDsaSigCtx* ctx, OSSL_PARAM* params)
{
    int ok = 1;
    OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_get_ctx_params");

    if (ctx == NULL) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL) {
            ok = wp_slhdsa_get_alg_id(ctx, p);
        }
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static const OSSL_PARAM* wp_slhdsa_gettable_ctx_params(wp_SlhDsaSigCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_slhdsa_gettable[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_slhdsa_gettable;
}

/* Honor the FIPS 205 signature params OpenSSL drives SLH-DSA with: context
 * string, deterministic/hedged selection, and a test-only randomizer.
 * message-encoding selects pure (1) or the pre-built FIPS 205 M' (0). */
static int wp_slhdsa_set_ctx_params(wp_SlhDsaSigCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;
    unsigned char context[WP_SLHDSA_CTX_MAX];
    size_t contextLen;
    unsigned char testEntropy[WP_SLHDSA_RND_MAX];
    size_t testEntropyLen;
    unsigned int deterministic;
    unsigned int rawMsg;
    unsigned char* verifySig = NULL;
    size_t verifySigLen = 0;
    int setVerifySig = 0;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_set_ctx_params");

    if (ctx == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (params == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
        return 1;
    }

    XMEMSET(context, 0, sizeof(context));
    XMEMCPY(context, ctx->context, ctx->contextLen);
    contextLen = ctx->contextLen;
    XMEMSET(testEntropy, 0, sizeof(testEntropy));
    XMEMCPY(testEntropy, ctx->testEntropy, ctx->testEntropyLen);
    testEntropyLen = ctx->testEntropyLen;
    deterministic = ctx->deterministic;
    rawMsg = ctx->rawMsg;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p != NULL) {
        void* vp = context;
        size_t len = 0;

        /* Changing the context mid-stream would sign a different M' than the
         * accumulated message was started under. */
        if (ctx->mdLen > 0) {
            ok = 0;
        }
        if (ok && !OSSL_PARAM_get_octet_string(p, &vp, sizeof(context),
                &len)) {
            ok = 0;
        }
        if (ok) {
            contextLen = len;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY);
        if (p != NULL) {
            void* vp = testEntropy;
            size_t len = 0;

            if (!OSSL_PARAM_get_octet_string(p, &vp,
                    sizeof(testEntropy), &len)) {
                ok = 0;
            }
            /* addrnd is exactly n bytes. A short value would silently fall
             * back to hedged signing, breaking the caller's reproducibility. */
            if (ok && (len != (size_t)wp_slhdsa_get_n(ctx->slhdsa))) {
                ok = 0;
            }
            if (ok) {
                testEntropyLen = len;
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC);
        if (p != NULL) {
            int det = 0;
            if (!OSSL_PARAM_get_int(p, &det)) {
                ok = 0;
            }
            if (ok) {
                deterministic = (det != 0);
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params,
            OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING);
        if (p != NULL) {
            int enc = 0;
            /* 1 builds M' from the message here; 0 means the caller already
             * did, per the FIPS 205 internal interface. Changing it mid-stream
             * would reinterpret the accumulated bytes under a different domain
             * separation, so refuse once input has been consumed. */
            if (ctx->mdLen > 0) {
                ok = 0;
            }
            if (ok && (!OSSL_PARAM_get_int(p, &enc) ||
                    ((enc != 0) && (enc != 1)))) {
                ok = 0;
            }
            if (ok) {
                rawMsg = (enc == 0);
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_SIGNATURE);
        if (p != NULL) {
            /* Reject malformed signatures before allocating a copy. */
            if ((p->data_size != (size_t)wp_slhdsa_get_sig_size(ctx->slhdsa)) ||
                    !OSSL_PARAM_get_octet_string(p, (void**)&verifySig, 0,
                        &verifySigLen)) {
                ok = 0;
            }
            if (ok) {
                setVerifySig = 1;
            }
        }
    }
    if (ok) {
        XMEMCPY(ctx->context, context, sizeof(context));
        ctx->contextLen = contextLen;
        XMEMCPY(ctx->testEntropy, testEntropy, sizeof(testEntropy));
        ctx->testEntropyLen = testEntropyLen;
        ctx->deterministic = deterministic;
        ctx->rawMsg = rawMsg;
        if (setVerifySig) {
            OPENSSL_free(ctx->verifySig);
            ctx->verifySig = verifySig;
            ctx->verifySigLen = verifySigLen;
            verifySig = NULL;
        }
    }
    OPENSSL_free(verifySig);
    wc_ForceZero(testEntropy, sizeof(testEntropy));
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static const OSSL_PARAM* wp_slhdsa_settable_ctx_params(wp_SlhDsaSigCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_slhdsa_settable[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, NULL, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, NULL),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, NULL),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_slhdsa_settable;
}

/* Verify-only builds omit the sign entry points entirely rather than stubbing
 * them: OpenSSL then reports "operation not supported for this key type". */
#ifdef WP_HAVE_SLHDSA_PRIVATE
#define WP_SLHDSA_SIGN_DISPATCH                                                \
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,                                           \
        (DFUNC)wp_slhdsa_sign_init                            },               \
    { OSSL_FUNC_SIGNATURE_SIGN,                                                \
        (DFUNC)wp_slhdsa_sign                                 },               \
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,                                    \
        (DFUNC)wp_slhdsa_digest_sign_init                     },               \
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,                                  \
        (DFUNC)wp_slhdsa_digest_signverify_update             },               \
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,                                   \
        (DFUNC)wp_slhdsa_digest_sign_final                    },
#else
#define WP_SLHDSA_SIGN_DISPATCH
#endif

#ifdef WP_HAVE_SLHDSA_PRIVATE
#define WP_SLHDSA_SIGN_MESSAGE_DISPATCH                                        \
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,                                   \
        (DFUNC)wp_slhdsa_message_init                         },               \
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,                                 \
        (DFUNC)wp_slhdsa_digest_signverify_update             },               \
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,                                  \
        (DFUNC)wp_slhdsa_sign_message_final                   },
#else
#define WP_SLHDSA_SIGN_MESSAGE_DISPATCH
#endif
#define WP_SLHDSA_VERIFY_MESSAGE_DISPATCH                                      \
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,                                 \
        (DFUNC)wp_slhdsa_verify_message_init                  },               \
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,                               \
        (DFUNC)wp_slhdsa_digest_signverify_update             },               \
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,                                \
        (DFUNC)wp_slhdsa_verify_message_final                 },

/* Dispatch table shared by all SLH-DSA parameter sets. */
const OSSL_DISPATCH wp_slhdsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,
        (DFUNC)wp_slhdsa_newctx                               },
    { OSSL_FUNC_SIGNATURE_FREECTX,
        (DFUNC)wp_slhdsa_freectx                              },
    { OSSL_FUNC_SIGNATURE_DUPCTX,
        (DFUNC)wp_slhdsa_dupctx                               },
    WP_SLHDSA_SIGN_DISPATCH
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        (DFUNC)wp_slhdsa_verify_init                          },
    { OSSL_FUNC_SIGNATURE_VERIFY,
        (DFUNC)wp_slhdsa_verify                               },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        (DFUNC)wp_slhdsa_digest_verify_init                   },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
        (DFUNC)wp_slhdsa_digest_signverify_update             },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
        (DFUNC)wp_slhdsa_digest_verify_final                  },
    WP_SLHDSA_SIGN_MESSAGE_DISPATCH
    WP_SLHDSA_VERIFY_MESSAGE_DISPATCH
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        (DFUNC)wp_slhdsa_get_ctx_params                       },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        (DFUNC)wp_slhdsa_gettable_ctx_params                  },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        (DFUNC)wp_slhdsa_set_ctx_params                       },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        (DFUNC)wp_slhdsa_settable_ctx_params                  },
    { 0, NULL }
};

#endif /* WP_HAVE_SLHDSA */

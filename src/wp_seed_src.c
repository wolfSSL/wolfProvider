/* wp_seed_src.c
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

#include <wolfprovider/settings.h>

#if defined(WP_HAVE_SEED_SRC) && defined(WP_HAVE_RANDOM)

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>

#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>

/* Include wolfSSL port header for XREAD/XCLOSE macros. */
#include <wolfssl/wolfcrypt/wc_port.h>

/* SEED-SRC reads /dev/urandom through wolfSSL's XREAD/XCLOSE, which wc_port.h
 * only defines when file/directory support is enabled. NO_WOLFSSL_DIR builds
 * are intentionally unsupported for SEED-SRC: fail with a clear message here
 * rather than a cryptic "XREAD undefined" later. */
#if defined(NO_WOLFSSL_DIR)
    #error "wolfProvider SEED-SRC requires wolfSSL file support; NO_WOLFSSL_DIR builds are unsupported. Rebuild wolfSSL without NO_WOLFSSL_DIR, or disable SEED-SRC."
#endif

#ifndef XBADFD
    #define XBADFD -1
#endif
#ifndef O_CLOEXEC
    #define O_CLOEXEC 0
#endif

#define URANDOM_PATH "/dev/urandom"

#ifndef WP_SINGLE_THREADED
    #define WP_URANDOM_LOCK()   wc_LockMutex(wp_get_urandom_mutex())
    #define WP_URANDOM_UNLOCK() wc_UnLockMutex(wp_get_urandom_mutex())
#else
    #define WP_URANDOM_LOCK()   (0)
    #define WP_URANDOM_UNLOCK() (void)0
#endif

/* Cached /dev/urandom fd, shared across provider contexts and reference
 * counted. Kept open so forked children inherit it and can read under a
 * seccomp sandbox that blocks open()/openat(). */
static int g_urandom_fd = XBADFD;

/* Live provider contexts referencing the shared fd/callback; mutex-guarded. */
static int g_urandom_ref_count = 0;

#ifdef WC_RNG_SEED_CB
static int g_seed_cb_registered = 0;
#endif

/**
 * Open the cached /dev/urandom fd if not already open. Idempotent; caller must
 * hold the urandom mutex.
 *
 * @return  0 on success.
 * @return  -1 if /dev/urandom cannot be opened.
 */
static int wp_urandom_open_locked(void)
{
    if (g_urandom_fd == XBADFD) {
        do {
            g_urandom_fd = open(URANDOM_PATH, O_RDONLY | O_CLOEXEC);
        } while (g_urandom_fd == XBADFD && errno == EINTR);

        if (g_urandom_fd == XBADFD) {
            WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG,
                "wp_urandom_open: failed to open " URANDOM_PATH);
            return -1;
        }
        WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG,
            "wp_urandom_open: opened " URANDOM_PATH);
    }

    return 0;
}

/**
 * Read exactly len bytes from the cached /dev/urandom fd, retrying on EINTR.
 * Caller must hold the urandom mutex.
 *
 * @param [out] buf  Buffer to fill.
 * @param [in]  len  Number of bytes to read; must not exceed INT_MAX.
 * @return  len on success.
 * @return  -1 on failure, or if len exceeds INT_MAX.
 */
static int wp_urandom_read_locked(unsigned char* buf, size_t len)
{
    size_t total = 0;

    if (len > (size_t)INT_MAX) {
        WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG,
            "wp_urandom_read: requested length too large");
        return -1;
    }

    if (wp_urandom_open_locked() != 0) {
        return -1;
    }

    while (total < len) {
        size_t toRead = len - total;
        ssize_t bytesRead;

        bytesRead = XREAD(g_urandom_fd, buf + total, toRead);

        if (bytesRead > 0) {
            total += (size_t)bytesRead;
        }
        else if (bytesRead < 0 && errno == EINTR) {
            continue;
        }
        else {
            WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG,
                "wp_urandom_read: XREAD failed");
            return -1;
        }
    }

    return (int)total;
}

/**
 * wolfSSL seed callback: fills seed from the cached /dev/urandom fd. Called by
 * wolfSSL's DRBG when it needs entropy (including after fork).
 *
 * @param [in]  os    Unused.
 * @param [out] seed  Buffer to fill.
 * @param [in]  sz    Number of bytes to generate.
 * @return  0 on success.
 * @return  -1 on failure.
 */
#ifdef WC_RNG_SEED_CB
static int wp_wolfssl_seed_cb(OS_Seed* os, byte* seed, word32 sz)
{
    int rc;

    (void)os;

    if (WP_URANDOM_LOCK() != 0) {
        return -1;
    }

    rc = wp_urandom_read_locked(seed, sz);

    WP_URANDOM_UNLOCK();

    return (rc >= 0 && (size_t)rc == (size_t)sz) ? 0 : -1;
}
#endif /* WC_RNG_SEED_CB */

/**
 * Take one reference on the shared urandom subsystem. The seed callback is
 * re-registered on every call because provider init resets wolfSSL's global
 * callback. Balance each successful call with one wp_urandom_cleanup().
 *
 * @return  0 on success.
 * @return  -1 on failure.
 */
int wp_urandom_init(void)
{
#ifdef WC_RNG_SEED_CB
    int firstRef;
#endif

    if (WP_URANDOM_LOCK() != 0) {
        return -1;
    }

    if (g_urandom_ref_count == INT_MAX) {
        WP_URANDOM_UNLOCK();
        return -1;
    }

#ifdef WC_RNG_SEED_CB
    firstRef = (g_urandom_ref_count == 0);
#endif
    g_urandom_ref_count++;

#ifdef WC_RNG_SEED_CB
    if (wc_SetSeed_Cb(wp_wolfssl_seed_cb) != 0) {
        WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG,
            "wc_SetSeed_Cb failed to register seed callback");
        /* Non-fatal - continue without callback */
    }
    else {
        g_seed_cb_registered = 1;
        if (firstRef) {
            WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG,
                "wp_urandom_init: registered wolfSSL seed callback");
        }
        else {
            WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG,
                "wp_urandom_init: re-registered wolfSSL seed callback");
        }
    }
#endif

    WP_URANDOM_UNLOCK();

    return 0;
}

/**
 * Release one reference taken by wp_urandom_init(). On the last reference,
 * close the cached fd and restore wolfSSL's default seed callback. No-op if the
 * reference count is already zero.
 */
void wp_urandom_cleanup(void)
{
    if (WP_URANDOM_LOCK() != 0) {
        return;
    }

    if (g_urandom_ref_count == 0) {
        WP_URANDOM_UNLOCK();
        return;
    }

    g_urandom_ref_count--;
    if (g_urandom_ref_count > 0) {
        WP_URANDOM_UNLOCK();
        return;
    }

#ifdef WC_RNG_SEED_CB
    /* Restore wolfSSL's default seed callback rather than NULL: a later
     * wc_InitRng() in the same process would otherwise fail with
     * DRBG_NO_SEED_CB. wc_GenerateSeed is the baseline provider init installs. */
    if (g_seed_cb_registered) {
        wc_SetSeed_Cb(wc_GenerateSeed);
        g_seed_cb_registered = 0;
    }
#endif

    if (g_urandom_fd != XBADFD) {
        XCLOSE(g_urandom_fd);
        g_urandom_fd = XBADFD;
        WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG,
            "wp_urandom_cleanup: closed " URANDOM_PATH);
    }

    WP_URANDOM_UNLOCK();
}

/**
 * Read random bytes from /dev/urandom (public entry; takes the urandom mutex).
 *
 * @param [out] buf  Buffer to fill.
 * @param [in]  len  Number of bytes to read.
 * @return  Number of bytes read on success.
 * @return  -1 on failure.
 */
int wp_urandom_read(unsigned char* buf, size_t len)
{
    int rc;

    if (buf == NULL || len == 0) {
        return -1;
    }

    if (WP_URANDOM_LOCK() != 0) {
        return -1;
    }

    rc = wp_urandom_read_locked(buf, len);

    WP_URANDOM_UNLOCK();

    return rc;
}


/**
 * SEED-SRC context structure.
 *
 * SEED-SRC acts as the root entropy source in OpenSSL's DRBG hierarchy.
 * It uses the provider context's pre-seeded WC_RNG which was initialized
 * at provider load time (before any sandbox restrictions).
 */
typedef struct wp_SeedSrcCtx {
    /** Provider context containing pre-seeded WC_RNG. */
    WOLFPROV_CTX* provCtx;
    /** Current state of the SEED-SRC. */
    int state;
} wp_SeedSrcCtx;

static int wp_seed_src_adin_mix_in(unsigned char *buf, size_t bufLen,
    const unsigned char *adin, size_t adinLen)
{
    if (adin == NULL || adinLen == 0)
        /* Nothing to mix in -> success */
        return 1;

    if ((buf == NULL) || (bufLen == 0)) {
        return 0;
    }

    if (adin != NULL && adinLen > 0) {
        size_t i;

        /* xor the additional data into the pool */
        for (i = 0; i < adinLen; ++i)
            buf[i % bufLen] ^= adin[i];
    }

    return 1;
}

/**
 * Create a new SEED-SRC context object.
 *
 * @param [in] provCtx         Provider context.
 * @param [in] parent          Parent RNG (unused for SEED-SRC, it's the root).
 * @param [in] parent_dispatch Parent dispatch table (unused).
 * @return  SEED-SRC context object on success.
 * @return  NULL on failure.
 */
static wp_SeedSrcCtx* wp_seed_src_new(WOLFPROV_CTX* provCtx, void* parent,
    const OSSL_DISPATCH* parent_dispatch)
{
    wp_SeedSrcCtx* ctx = NULL;

    (void)parent;
    (void)parent_dispatch;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_seed_src_new");

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
        if (ctx != NULL) {
            ctx->provCtx = provCtx;
            ctx->state = EVP_RAND_STATE_UNINITIALISED;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        ctx != NULL);
    return ctx;
}

/**
 * Free the SEED-SRC context object.
 *
 * @param [in, out] ctx  SEED-SRC context object.
 */
static void wp_seed_src_free(wp_SeedSrcCtx* ctx)
{
    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_seed_src_free");

    if (ctx != NULL) {
        /* Don't free provCtx->rng - it's owned by the provider context */
        OPENSSL_free(ctx);
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        1);
}

/**
 * Instantiate the SEED-SRC.
 *
 * Since the provider context's RNG is already initialized at provider load
 * time, this just marks the SEED-SRC as ready.
 *
 * @param [in, out] ctx         SEED-SRC context object.
 * @param [in]      strength    Strength in bits required.
 * @param [in]      predResist  Prediction resistance required.
 * @param [in]      pStr        Personalization string (unused).
 * @param [in]      pStrLen     Length of personalization string.
 * @param [in]      params      Other parameters (unused).
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_seed_src_instantiate(wp_SeedSrcCtx* ctx, unsigned int strength,
    int predResist, const unsigned char* pStr, size_t pStrLen,
    const OSSL_PARAM params[])
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_seed_src_instantiate");

    (void)strength;
    (void)predResist;
    (void)pStr;
    (void)pStrLen;
    (void)params;

    if (ctx->provCtx == NULL) {
        ok = 0;
    }
    else {
        /* The provider context's RNG is already seeded from provider init */
        ctx->state = EVP_RAND_STATE_READY;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        ok);
    return ok;
}

/**
 * Uninstantiate the SEED-SRC.
 *
 * @param [in, out] ctx  SEED-SRC context object.
 * @return  1 on success.
 */
static int wp_seed_src_uninstantiate(wp_SeedSrcCtx* ctx)
{
    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_seed_src_uninstantiate");

    ctx->state = EVP_RAND_STATE_UNINITIALISED;

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        1);
    return 1;
}

/**
 * Generate random data from the SEED-SRC.
 *
 * Uses the provider context's pre-seeded WC_RNG to generate random bytes.
 * This does not require any file I/O since the RNG was seeded at provider
 * load time.
 *
 * @param [in, out] ctx         SEED-SRC context object.
 * @param [out]     out         Buffer to write random data to.
 * @param [in]      outLen      Length of output buffer.
 * @param [in]      strength    Strength in bits required.
 * @param [in]      predResist  Prediction resistance required.
 * @param [in]      addIn       Additional input (unused).
 * @param [in]      addInLen    Length of additional input.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_seed_src_generate(wp_SeedSrcCtx* ctx, unsigned char* out,
    size_t outLen, unsigned int strength, int predResist,
    const unsigned char* addIn, size_t addInLen)
{
    int ok = 1;
    unsigned char *buf = NULL;
    int rc;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_seed_src_generate");

    (void)strength;
    (void)predResist;

    if (ctx->state != EVP_RAND_STATE_READY) {
        ok = 0;
    }
    if (ok && ctx->provCtx == NULL) {
        ok = 0;
    }
    if (ok) {
        buf = OPENSSL_zalloc(outLen);
        if (buf == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        /*
         * Read directly from /dev/urandom.
         * The file is opened lazily on first request and kept open, so child
         * processes can inherit the fd and read even in seccomp sandboxes.
         */
        rc = wp_urandom_read(buf, outLen);
        if (rc < 0 || (size_t)rc != outLen) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_RNG,
                "wp_urandom_read failed", rc);
            ok = 0;
        }
    }
    if (ok) {
        /* Mix in additional input if provided */
        ok = wp_seed_src_adin_mix_in(buf, outLen, addIn, addInLen);
    }
    if (ok) {
        memcpy(out, buf, outLen);
    }
    if (buf != NULL) {
        OPENSSL_clear_free(buf, outLen);
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        ok);
    return ok;
}

/*
 * SEED-SRC locking functions.
 *
 * These are no-ops, matching OpenSSL's default provider implementation.
 * The DRBG layer that uses SEED-SRC as a parent has its own locking mechanism,
 * so SEED-SRC itself doesn't need to expose locking via the provider API.
 *
 * Note: The actual seed generation in wp_urandom_read() and wp_wolfssl_seed_cb()
 * uses internal mutex protection for thread-safe access to the shared file handle.
 */

/**
 * Enable locking on the SEED-SRC context.
 *
 * No-op - matches OpenSSL's SEED-SRC implementation.
 *
 * @param [in, out] ctx  SEED-SRC context object (unused).
 * @return  1 always.
 */
static int wp_seed_src_enable_locking(wp_SeedSrcCtx* ctx)
{
    (void)ctx;
    return 1;
}

/**
 * Lock the SEED-SRC context.
 *
 * No-op - matches OpenSSL's SEED-SRC implementation.
 *
 * @param [in, out] ctx  SEED-SRC context object (unused).
 * @return  1 always.
 */
static int wp_seed_src_lock(wp_SeedSrcCtx* ctx)
{
    (void)ctx;
    return 1;
}

/**
 * Unlock the SEED-SRC context.
 *
 * No-op - matches OpenSSL's SEED-SRC implementation.
 *
 * @param [in, out] ctx  SEED-SRC context object (unused).
 * @return  1 always.
 */
static int wp_seed_src_unlock(wp_SeedSrcCtx* ctx)
{
    (void)ctx;
    return 1;
}

/**
 * Return an array of supported gettable parameters for the SEED-SRC context.
 *
 * @param [in] ctx      SEED-SRC context object (unused).
 * @param [in] provCtx  Provider context object (unused).
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_seed_src_gettable_ctx_params(wp_SeedSrcCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_supported_gettable_seed_src_ctx_params[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };

    (void)ctx;
    (void)provCtx;

    return wp_supported_gettable_seed_src_ctx_params;
}

/**
 * Get the SEED-SRC context parameters.
 *
 * @param [in]      ctx     SEED-SRC context object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_seed_src_get_ctx_params(wp_SeedSrcCtx* ctx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_seed_src_get_ctx_params");

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if ((p != NULL) && (!OSSL_PARAM_set_int(p, ctx->state))) {
        ok = 0;
    }
    if (ok) {
        /* TODO: review strength value */
        p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
        if ((p != NULL) && (!OSSL_PARAM_set_uint(p, 256))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, (1 << 16)))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        ok);
    return ok;
}

/**
 * Get seed from the SEED-SRC for a child DRBG.
 *
 * Uses the provider context's pre-seeded WC_RNG to generate seed bytes.
 * This does not require any file I/O since the RNG was seeded at provider
 * load time (before any sandbox restrictions).
 *
 * @param [in, out] ctx                  SEED-SRC context object.
 * @param [out]     pSeed                Handle to seed buffer.
 * @param [in]      entropy              Number of entropy bits required.
 * @param [in]      minLen               Minimum length of buffer in bytes.
 * @param [in]      maxLen               Maximum length of buffer in bytes.
 * @param [in]      prediction_resistance Prediction resistance required.
 * @param [in]      addIn                Additional input.
 * @param [in]      addInLen             Length of additional input.
 * @return  Length of seed on success.
 * @return  0 on failure.
 */
static size_t wp_seed_src_get_seed(wp_SeedSrcCtx* ctx, unsigned char** pSeed,
    int entropy, size_t minLen, size_t maxLen, int prediction_resistance,
    const unsigned char* addIn, size_t addInLen)
{
    size_t ret = 0;
    unsigned char* buffer = NULL;
    int rc;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_seed_src_get_seed");

    (void)entropy;
    (void)maxLen;
    (void)prediction_resistance;

    if (ctx->state != EVP_RAND_STATE_READY) {
        goto end;
    }

    if (ctx->provCtx == NULL) {
        goto end;
    }

    buffer = OPENSSL_zalloc(minLen);
    if (buffer == NULL) {
        goto end;
    }

    /*
     * Read directly from /dev/urandom.
     * The file is opened lazily on first request and kept open, so child
     * processes can inherit the fd and read even in seccomp sandboxes.
     */
    rc = wp_urandom_read(buffer, minLen);
    if (rc < 0 || (size_t)rc != minLen) {
        WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_RNG,
            "wp_urandom_read failed", rc);
        OPENSSL_clear_free(buffer, minLen);
        buffer = NULL;
        goto end;
    }

    /* Mix in additional input if provided */
    if (!wp_seed_src_adin_mix_in(buffer, minLen, addIn, addInLen)) {
        OPENSSL_clear_free(buffer, minLen);
        buffer = NULL;
        goto end;
    }

    *pSeed = buffer;
    buffer = NULL;
    ret = minLen;

end:
    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        ret > 0);
    return ret;
}

/**
 * Securely zeroize and free the seed buffer.
 *
 * @param [in]      ctx      SEED-SRC context object (unused).
 * @param [in, out] seed     Seed to zeroize.
 * @param [in]      seedLen  Length of seed in bytes.
 */
static void wp_seed_src_clear_seed(wp_SeedSrcCtx* ctx, unsigned char* seed,
    size_t seedLen)
{
    (void)ctx;
    OPENSSL_secure_clear_free(seed, seedLen);
}

/**
 * Verify zeroization of the SEED-SRC components.
 *
 * @param [in] ctx  SEED-SRC context object (unused).
 * @return  1 on success.
 */
static int wp_seed_src_verify_zeroization(wp_SeedSrcCtx* ctx)
{
    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_seed_src_verify_zeroization");

    (void)ctx;

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        1);
    return 1;
}


/** Dispatch table for SEED-SRC. */
const OSSL_DISPATCH wp_seed_src_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX,              (DFUNC)wp_seed_src_new              },
    { OSSL_FUNC_RAND_FREECTX,             (DFUNC)wp_seed_src_free             },
    { OSSL_FUNC_RAND_INSTANTIATE,         (DFUNC)wp_seed_src_instantiate      },
    { OSSL_FUNC_RAND_UNINSTANTIATE,       (DFUNC)wp_seed_src_uninstantiate    },
    { OSSL_FUNC_RAND_GENERATE,            (DFUNC)wp_seed_src_generate         },
    { OSSL_FUNC_RAND_ENABLE_LOCKING,      (DFUNC)wp_seed_src_enable_locking   },
    { OSSL_FUNC_RAND_LOCK,                (DFUNC)wp_seed_src_lock             },
    { OSSL_FUNC_RAND_UNLOCK,              (DFUNC)wp_seed_src_unlock           },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (DFUNC)wp_seed_src_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS,      (DFUNC)wp_seed_src_get_ctx_params   },
    { OSSL_FUNC_RAND_GET_SEED,            (DFUNC)wp_seed_src_get_seed         },
    { OSSL_FUNC_RAND_CLEAR_SEED,          (DFUNC)wp_seed_src_clear_seed       },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION,  (DFUNC)wp_seed_src_verify_zeroization },
    { 0, NULL }
};

#endif /* WP_HAVE_SEED_SRC && WP_HAVE_RANDOM */

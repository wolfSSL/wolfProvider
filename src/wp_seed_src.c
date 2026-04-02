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

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>

#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>

/* Include wolfSSL port header for XFOPEN/XFREAD/XFCLOSE macros */
#include <wolfssl/wolfcrypt/wc_port.h>

/*
 * /dev/urandom file caching for fork-safe entropy.
 *
 * These functions manage a cached file handle to /dev/urandom that is
 * opened lazily on first entropy request and kept open. This matches
 * OpenSSL's default provider behavior. The file stays open so child
 * processes after fork() can inherit the underlying fd and read from it
 * without needing to call openat(), which may be blocked by seccomp sandboxes.
 */

#define URANDOM_PATH "/dev/urandom"

/*
 * Helper macros for thread-safe urandom access.
 * These expand to no-ops when WP_SINGLE_THREADED is defined.
 */
#ifndef WP_SINGLE_THREADED
    #define WP_URANDOM_LOCK()   wc_LockMutex(wp_get_urandom_mutex())
    #define WP_URANDOM_UNLOCK() wc_UnLockMutex(wp_get_urandom_mutex())
#else
    #define WP_URANDOM_LOCK()   (0)
    #define WP_URANDOM_UNLOCK() (void)0
#endif

/*
 * Global cached /dev/urandom file handle.
 * Opened lazily on first entropy request, kept open for the lifetime of the
 * provider. This matches OpenSSL's model where random devices are opened
 * on-demand and cached.
 */
static XFILE g_urandom_file = XBADFILE;

/*
 * Flag indicating whether the seed callback has been registered.
 */
#ifdef WC_RNG_SEED_CB
static int g_seed_cb_registered = 0;
#endif

/**
 * wolfSSL seed callback that uses the cached /dev/urandom file.
 *
 * This callback is registered with wc_SetSeed_Cb() and is called by wolfSSL's
 * DRBG when it needs entropy (including after fork detection).
 *
 * @param [in]  os    OS_Seed structure (unused)
 * @param [out] seed  Buffer to fill with seed data
 * @param [in]  sz    Number of bytes to generate
 * @return  0 on success
 * @return  -1 on failure
 */
#ifdef WC_RNG_SEED_CB
static int wp_wolfssl_seed_cb(OS_Seed* os, byte* seed, word32 sz)
{
    size_t bytesRead;
    size_t total = 0;

    (void)os;

    /* Lock before checking/opening file to prevent race conditions.
     * The urandom mutex is initialized via constructor at library load,
     * so it's guaranteed to be ready for use here.
     */
    if (WP_URANDOM_LOCK() != 0) {
        return -1;
    }

    /* Lazy open: open file on first entropy request */
    if (g_urandom_file == XBADFILE) {
        g_urandom_file = XFOPEN(URANDOM_PATH, "rb");
        if (g_urandom_file == XBADFILE) {
            WP_URANDOM_UNLOCK();
            return -1;
        }
    }

    /* Read until we have all the bytes we need */
    while (total < sz) {
        bytesRead = XFREAD(seed + total, 1, sz - total, g_urandom_file);
        if (bytesRead > 0) {
            total += bytesRead;
        }
        else {
            /* EOF or error */
            WP_URANDOM_UNLOCK();
            return -1;
        }
    }

    WP_URANDOM_UNLOCK();

    return 0;
}
#endif /* WC_RNG_SEED_CB */

/**
 * Initialize the urandom subsystem.
 *
 * This performs lazy initialization - the file handle is not opened until
 * first entropy request. This matches OpenSSL's default provider behavior.
 * The seed callback is registered here so wolfSSL can use our entropy source.
 *
 * @return  0 on success.
 * @return  -1 on failure.
 */
int wp_urandom_init(void)
{
    /* Lock to ensure thread-safe initialization.
     * The urandom mutex is initialized via constructor at library load.
     */
    if (WP_URANDOM_LOCK() != 0) {
        return -1;
    }

    /* Initialize global file handle to invalid - will be opened lazily */
    g_urandom_file = XBADFILE;

#ifdef WC_RNG_SEED_CB
    /* Register our seed callback with wolfSSL.
     * This is critical for fork safety - wolfSSL will call this callback
     * instead of wc_GenerateSeed() when it needs to reseed after fork.
     * The callback will open the file lazily on first use.
     */
    if (!g_seed_cb_registered) {
        if (wc_SetSeed_Cb(wp_wolfssl_seed_cb) != 0) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG,
                "wc_SetSeed_Cb failed", -1);
            /* Non-fatal - continue without callback */
        }
        else {
            g_seed_cb_registered = 1;
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG,
                "wp_urandom_init: registered wolfSSL seed callback", 0);
        }
    }
#endif

    WP_URANDOM_UNLOCK();

    return 0;
}

/**
 * Clean up the urandom subsystem.
 *
 * Closes the cached file handle if it was opened, and unregisters
 * the seed callback.
 */
void wp_urandom_cleanup(void)
{
    /* Lock to ensure thread-safe cleanup.
     * The urandom mutex is initialized via constructor at library load.
     */
    if (WP_URANDOM_LOCK() != 0) {
        return;
    }

#ifdef WC_RNG_SEED_CB
    /* Unregister seed callback */
    if (g_seed_cb_registered) {
        wc_SetSeed_Cb(NULL);
        g_seed_cb_registered = 0;
    }
#endif

    /* Close global file if it was opened */
    if (g_urandom_file != XBADFILE) {
        XFCLOSE(g_urandom_file);
        g_urandom_file = XBADFILE;
        WOLFPROV_MSG_DEBUG(WP_LOG_LEVEL_DEBUG,
            "wp_urandom_cleanup: closed " URANDOM_PATH);
    }

    WP_URANDOM_UNLOCK();

    /* Note: global urandom mutex is managed via constructor/destructor */
}

/**
 * Read random bytes from /dev/urandom.
 *
 * Opens /dev/urandom lazily on first call, then keeps it open for subsequent
 * reads. This matches OpenSSL's default provider behavior. The file stays open
 * so child processes can inherit it and read even in sandboxed environments.
 *
 * @param [out] buf      Buffer to fill with random bytes.
 * @param [in]  len      Number of bytes to read.
 * @return  Number of bytes read on success.
 * @return  -1 on failure.
 */
int wp_urandom_read(unsigned char* buf, size_t len)
{
    size_t bytesRead;
    size_t total = 0;

    if (buf == NULL || len == 0) {
        return -1;
    }

    if (WP_URANDOM_LOCK() != 0) {
        return -1;
    }

    /* Lazy open: open file on first entropy request */
    if (g_urandom_file == XBADFILE) {
        g_urandom_file = XFOPEN(URANDOM_PATH, "rb");
        if (g_urandom_file == XBADFILE) {
            WOLFPROV_MSG_DEBUG(WP_LOG_LEVEL_DEBUG,
                "wp_urandom_read: failed to open " URANDOM_PATH);
            WP_URANDOM_UNLOCK();
            return -1;
        }
        WOLFPROV_MSG_DEBUG(WP_LOG_LEVEL_DEBUG,
            "wp_urandom_read: opened " URANDOM_PATH);
    }

    /* Read until we have all the bytes we need */
    while (total < len) {
        bytesRead = XFREAD(buf + total, 1, len - total, g_urandom_file);
        if (bytesRead > 0) {
            total += bytesRead;
        }
        else {
            /* EOF or error - shouldn't happen with /dev/urandom */
            WOLFPROV_MSG_DEBUG(WP_LOG_LEVEL_DEBUG,
                "wp_urandom_read: XFREAD failed");
            WP_URANDOM_UNLOCK();
            return -1;
        }
    }

    WP_URANDOM_UNLOCK();

    return (int)total;
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
        if (rc != (int)outLen) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG,
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
        OPENSSL_free(buf);
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
    if (rc != (int)minLen) {
        WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG,
            "wp_urandom_read failed", rc);
        OPENSSL_free(buffer);
        buffer = NULL;
        goto end;
    }

    /* Mix in additional input if provided */
    if (!wp_seed_src_adin_mix_in(buffer, minLen, addIn, addInLen)) {
        OPENSSL_free(buffer);
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
    OPENSSL_secure_clear_free(seed, seedLen);
    if (ctx != NULL) {
        ctx->state = EVP_RAND_STATE_UNINITIALISED;
    }
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

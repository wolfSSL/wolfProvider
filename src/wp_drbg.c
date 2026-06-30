/* wp_drbg.c
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


#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>


/* TODO: Add seed. No API available. */


/** Maximum number of bytes per request for. */
#define WP_DRBG_MAX_REQUESTS    (1 << 16)

/**
 * wolfSSL's SHA-256 Hash DRBG security strength in bits.
 * See NIST SP-80-57 5.6.1.2 Table 3
 */
#define WP_DRBG_STRENGTH        256

/**
 * DRBG context structure.
 */
typedef struct wp_DrbgCtx {
    /** Provider context. */
    WOLFPROV_CTX* provCtx;
    /** wolfSSL random number generator. HASH DRBG implementation. */
    WC_RNG* rng;
#ifndef WP_SINGLE_THREADED
    /** Mutex for multithreading access to this DRBG context. */
    wolfSSL_Mutex* mutex;
#endif
    /** Parent DRBG context for getting entropy. */
    void* parent;
    /** Parent's get_seed function. */
    OSSL_FUNC_rand_get_seed_fn* parentGetSeed;
    /** Parent's clear_seed function. */
    OSSL_FUNC_rand_clear_seed_fn* parentClearSeed;
#ifndef WP_HAVE_DRBG_RESEED
    /** Set when a failed reseed re-instantiation left ctx->rng de-instantiated. */
    int rngError;
#endif
} wp_DrbgCtx;


/**
 * Create a new DRBG context object.
 *
 * The parent and parentDispatch parameters are supplied by OpenSSL when
 * creating a child DRBG in a hierarchy. When a child DRBG is created via
 * EVP_RAND_CTX_new(child_rand, parent_ctx), OpenSSL internally calls the
 * provider's OSSL_FUNC_RAND_NEWCTX with the parent context and its dispatch
 * table. This allows the child DRBG to obtain entropy from its parent
 * (via OSSL_FUNC_RAND_GET_SEED) instead of accessing /dev/urandom directly,
 * which is critical for seccomp sandbox compatibility.
 *
 * @param [in] provCtx         Provider context.
 * @param [in] parent          Parent DRBG context for getting entropy.
 *                             NULL for root DRBGs.
 * @param [in] parentDispatch  Parent's dispatch table containing get_seed
 *                             and clear_seed functions. NULL for root DRBGs.
 * @return  DRBG object on success.
 * @return  NULL on failure.
 */
static wp_DrbgCtx* wp_drbg_new(void* provCtx, void* parent,
    const OSSL_DISPATCH* parentDispatch)
{
    wp_DrbgCtx* ctx = NULL;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_drbg_new");

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = (WOLFPROV_CTX*)provCtx;
        ctx->parent = parent;

        /* Extract parent dispatch functions if available */
        if (parentDispatch != NULL) {
            for (; parentDispatch->function_id != 0; parentDispatch++) {
                switch (parentDispatch->function_id) {
                    case OSSL_FUNC_RAND_GET_SEED:
                        ctx->parentGetSeed =
                            OSSL_FUNC_rand_get_seed(parentDispatch);
                        break;
                    case OSSL_FUNC_RAND_CLEAR_SEED:
                        ctx->parentClearSeed =
                            OSSL_FUNC_rand_clear_seed(parentDispatch);
                        break;
                }
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        ctx != NULL);
    return ctx;
}

/**
 * Free the DRBG context object.
 *
 * @param [in, out] ctx  ECDH key exchange context object.
 */
static void wp_drbg_free(wp_DrbgCtx* ctx)
{
    if (ctx != NULL) {
    #ifndef WP_SINGLE_THREADED
        if (ctx->mutex != NULL) {
            wc_FreeMutex(ctx->mutex);
            OPENSSL_free(ctx->mutex);
        }
    #endif
    #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
        (void)wc_rng_free(ctx->rng);
    #else
        wc_FreeRng(ctx->rng);
        OPENSSL_clear_free(ctx->rng, sizeof(*ctx->rng));
    #endif
        OPENSSL_free(ctx);
    }
}

static int wp_drbg_uninstantiate(wp_DrbgCtx* ctx);
static int wp_drbg_reseed(wp_DrbgCtx* ctx, int predResist,
    const unsigned char* entropy, size_t entropyLen,
    const unsigned char* addIn, size_t addInLen);

/**
 * Instantiate a new DRBG.
 *
 * @param [in, out] ctx         DRBG context object.
 * @param [in]      strength    Strength in bits required.
 * @param [in]      predResist  Prediction resistance required.
 * @param [in]      pStr        Personalization string to instantiate with.
 * @param [in]      pStrLen     Length of personalization string in bytes.
 * @param [in]      params      Other parameters. Unused.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_drbg_instantiate(wp_DrbgCtx* ctx, unsigned int strength,
    int predResist, const unsigned char* pStr, size_t pStrLen,
    const OSSL_PARAM params[])
{
    int ok = 1;
    unsigned char* seed = NULL;
    size_t seedLen = 0;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_drbg_instantiate");

    (void)params;

    if (strength > WP_DRBG_STRENGTH) {
        ok = 0;
    }

    /* Free any existing DRBG before re-allocating to avoid a leak. */
    if (ok && ctx->rng != NULL) {
        wp_drbg_uninstantiate(ctx);
    }

    if (ok && ctx->parentGetSeed != NULL) {
        /* Get entropy from parent DRBG (no file I/O needed) */
        WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG,
            "Getting entropy from parent DRBG");

        seedLen = ctx->parentGetSeed(ctx->parent, &seed,
            256,  /* entropy bits */
            32,   /* min_len */
            256,  /* max_len */
            predResist, pStr, pStrLen);

        if (seedLen == 0 || seed == NULL) {
            WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG,
                "Failed to get seed from parent");
            ok = 0;
        }

        if (ok) {
            /* Route DRBG instantiation through the FIPS-validated
             * wc_InitRngNonce entry (not wc_rng_new), so it works on every
             * pinned FIPS bundle vintage. */
            ctx->rng = OPENSSL_zalloc(sizeof(*ctx->rng));
            if (ctx->rng == NULL) {
                ok = 0;
            }
        }

        if (ok) {
            int rc = wc_InitRngNonce(ctx->rng, seed, (word32)seedLen);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_RNG,
                    "wc_InitRngNonce", rc);
                OPENSSL_clear_free(ctx->rng, sizeof(*ctx->rng));
                ctx->rng = NULL;
                ok = 0;
            }
        }

        /* Clear the seed from parent */
        if (seed != NULL && ctx->parentClearSeed != NULL) {
            ctx->parentClearSeed(ctx->parent, seed, seedLen);
        }
    }
    else if (ok) {
        /* No parent - this is the root DRBG, use /dev/urandom directly.
         * This path should only be taken before sandbox activation. */
        WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG,
            "No parent DRBG, using direct seeding");

    #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
        ctx->rng = wc_rng_new((byte*)pStr, (word32)pStrLen, NULL);
        if (ctx->rng == NULL) {
            ok = 0;
        }
    #else
        (void)pStr;
        (void)pStrLen;

        ctx->rng = OPENSSL_zalloc(sizeof(*ctx->rng));
        if (ctx->rng == NULL) {
            ok = 0;
        }
        if (ok) {
            int rc = wc_InitRng(ctx->rng);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_RNG, "wc_InitRng", rc);
                OPENSSL_clear_free(ctx->rng, sizeof(*ctx->rng));
                ok = 0;
            }
        }
    #endif
    }

#ifndef WP_HAVE_DRBG_RESEED
    if (ok) {
        /* Clear any prior reseed error state. */
        ctx->rngError = 0;
    }
#endif

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Uninstatiate DRBG.
 *
 * @param [in, out] ct
 */
static int wp_drbg_uninstantiate(wp_DrbgCtx* ctx)
{
    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_drbg_uninstantiate");

#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
    (void)wc_rng_free(ctx->rng);
#else
    wc_FreeRng(ctx->rng);
    OPENSSL_clear_free(ctx->rng, sizeof(*ctx->rng));
#endif
    ctx->rng = NULL;
#ifndef WP_HAVE_DRBG_RESEED
    ctx->rngError = 0;
#endif
    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}


/**
 * Generate random data.
 *
 * @param [in, out] ctx         DRBG context object.
 * @param [out]     out         Buffer to hold generated random data.
 * @param [in]      outLen      Number of random bytes to generate.
 * @param [in]      strength    Strength in bits required.
 * @param [in]      predResist  Prediction resistance required. When set, the
 *                              DRBG is reseeded with fresh entropy before
 *                              generating (SP 800-90A 9.3.1). Honored only when
 *                              built with WP_HAVE_DRBG_RESEED; otherwise
 *                              ignored.
 * @param [in]      addIn       Additional input data. Ignored: wolfCrypt has no
 *                              public generate API that accepts additional
 *                              input on a live WC_RNG.
 * @param [in]      addInLen    Length of additional input data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_drbg_generate(wp_DrbgCtx* ctx, unsigned char* out,
    size_t outLen, unsigned int strength, int predResist,
    const unsigned char* addIn, size_t addInLen)
{
    int ok = 1;
    int rc;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_drbg_generate");

    if (strength > WP_DRBG_STRENGTH) {
        ok = 0;
    }
    if (ok && ctx->rng == NULL) {
        WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG, "DRBG not instantiated");
        ok = 0;
    }
#ifndef WP_HAVE_DRBG_RESEED
    if (ok && ctx->rngError) {
        WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG, "DRBG in error state");
        ok = 0;
    }
#endif

    if (ok && (outLen > 0xFFFFFFFFU)) {
        WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG, "Request length is too big");
        ok = 0;
    }

    /* wolfCrypt exposes no public generate API that accepts additional input on
     * a live WC_RNG (wc_RNG_GenerateBlock passes NULL to Hash_DRBG_Generate),
     * so addIn must be ignored. Per SP 800-90A additional_input on Generate is
     * optional, so dropping it is standards-compliant. */
    if (ok && (addInLen > 0)) {
        WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG, "Additional data ignored");
        (void)addIn;
    }

    /* SP 800-90A 9.3.1: prediction resistance requires reseeding with fresh
     * entropy immediately before generating. wolfCrypt's public generate API
     * has no PR flag, so emulate it via the in-place reseed path (fresh OS
     * entropy, no caller-supplied material). Only available where a true
     * reseed exists; without it the fallback re-instantiates the whole DRBG,
     * so predResist is ignored. */
#ifdef WP_HAVE_DRBG_RESEED
    if (ok && predResist) {
        if (!wp_drbg_reseed(ctx, 1, NULL, 0, NULL, 0)) {
            WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG,
                "Prediction resistance reseed failed");
            ok = 0;
        }
    }
#else
    (void)predResist;
#endif

    if (ok) {
        rc = wc_RNG_GenerateBlock(ctx->rng, out, (word32)outLen);
        if (rc != 0) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_RNG, "wc_RNG_GenerateBlock",
                rc);
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        ok);
    return ok;
}

/**
 * Reseed DRBG.
 *
 * Without WP_HAVE_DRBG_RESEED, re-instantiates instead of reseeding: @p entropy
 * and @p addIn become the nonce, not DRBG entropy_input.
 *
 * @param [in, out] ctx         DRBG context object.
 * @param [in]      predResist  Prediction resistance required.
 * @param [in]      entropy     Entropy data to reseed with.
 * @param [in]      entropyLen  Length of entropy data.
 * @param [in]      addIn       Additional input data to reseed with.
 * @param [in]      addInLen    Length of additional input data in bytes.
 * @param [in]      params      Other parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_drbg_reseed(wp_DrbgCtx* ctx, int predResist,
    const unsigned char* entropy, size_t entropyLen,
    const unsigned char* addIn, size_t addInLen)
{
    int ok = 1;
    int rc;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_drbg_reseed");

    /* Reseed requires an instantiated DRBG. */
    if (ctx->rng == NULL) {
        ok = 0;
    }

    /* wolfCrypt RNG APIs take word32 lengths; reject oversized inputs. */
    if (ok && entropy != NULL && entropyLen > 0xFFFFFFFFU) {
        ok = 0;
    }
    if (ok && addIn != NULL && addInLen > 0xFFFFFFFFU) {
        ok = 0;
    }

#ifdef WP_HAVE_DRBG_RESEED
    {
        unsigned char* seed = NULL;
        size_t seedLen = 0;

        /* No caller entropy: with SEED-SRC, draw from the cached /dev/urandom
         * fd (survives a seccomp sandbox); else wc_GenerateSeed(). */
        if (ok && (entropy == NULL || entropyLen == 0)) {
            seedLen = 48;
            seed = OPENSSL_malloc(seedLen);
            if (seed == NULL) {
                ok = 0;
            }
            if (ok) {
            #if defined(WP_HAVE_SEED_SRC) && defined(WP_HAVE_RANDOM)
                if (wp_urandom_read(seed, seedLen) != (int)seedLen) {
                    ok = 0;
                }
            #else
                OS_Seed osSeed;
                if (wc_GenerateSeed(&osSeed, seed, (word32)seedLen) != 0) {
                    ok = 0;
                }
            #endif
            }
            if (ok) {
                entropy = seed;
                entropyLen = seedLen;
            }
        }

        /* In-place SP 800-90A reseed via wolfCrypt's public DRBG API. */
        if (ok && entropy != NULL && entropyLen > 0) {
            rc = wc_RNG_DRBG_Reseed(ctx->rng, entropy, (word32)entropyLen);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_RNG,
                    "wc_RNG_DRBG_Reseed", rc);
                ok = 0;
            }
        }
        if (ok && (addInLen > 0) && (addIn != NULL)) {
            rc = wc_RNG_DRBG_Reseed(ctx->rng, addIn, (word32)addInLen);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_RNG,
                    "wc_RNG_DRBG_Reseed", rc);
                ok = 0;
            }
        }

        if (seed != NULL) {
            OPENSSL_clear_free(seed, seedLen);
        }
    }
#else
    /* No exported wc_RNG_DRBG_Reseed (e.g. cert4718): re-instantiate in place
     * via wc_FreeRng() + wc_InitRngNonce(), which self-seeds fresh entropy
     * (sandbox-safe when built with SEED-SRC). Caller entropy/addIn become
     * only the nonce. A failed re-init sets rngError. */
    if (ok) {
        unsigned char* nonce = NULL;
        word32 nonceLen = 0;
        word32 eLen = (entropy != NULL) ? (word32)entropyLen : 0;
        word32 aLen = (addIn != NULL) ? (word32)addInLen : 0;

        /* Build nonce = entropy || addIn (either may be absent). */
        if (aLen > (0xFFFFFFFFU - eLen)) {
            ok = 0;
        }
        if (ok && (eLen + aLen) > 0) {
            nonceLen = eLen + aLen;
            nonce = OPENSSL_malloc(nonceLen);
            if (nonce == NULL) {
                ok = 0;
            }
            else {
                if (eLen > 0) {
                    XMEMCPY(nonce, entropy, eLen);
                }
                if (aLen > 0) {
                    XMEMCPY(nonce + eLen, addIn, aLen);
                }
            }
        }
        if (ok) {
            wc_FreeRng(ctx->rng);
            rc = wc_InitRngNonce(ctx->rng, nonce, nonceLen);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_RNG,
                    "wc_InitRngNonce", rc);
                ctx->rngError = 1;
                ok = 0;
            }
            else {
                /* Recovered: clear any prior reseed error. */
                ctx->rngError = 0;
            }
        }
        if (nonce != NULL) {
            OPENSSL_clear_free(nonce, nonceLen);
        }
    }
#endif /* WP_HAVE_DRBG_RESEED */

    (void)predResist;

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Create a lock object for this DRBG context object.
 *
 * @param [in, out] ctx  DRBG context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_drbg_enable_locking(wp_DrbgCtx* ctx)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_drbg_enable_locking");

#ifndef WP_SINGLE_THREADED
    if (ctx->mutex == NULL) {
        ctx->mutex = OPENSSL_malloc(sizeof(*ctx->mutex));
        if (ctx->mutex == NULL) {
            ok = 0;
        }
        if (ok) {
            int rc = wc_InitMutex(ctx->mutex);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_RNG, "wc_InitMutex", rc);
                OPENSSL_free(ctx->mutex);
                ctx->mutex = NULL;
                ok = 0;
            }
        }
    }
#endif

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Lock the DRBG context object.
 *
 * @param [in, out] ctx  DRBG context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_drbg_lock(wp_DrbgCtx* ctx)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_drbg_lock");

#ifndef WP_SINGLE_THREADED
    int rc;

    if (ctx->mutex != NULL) {
        rc = wc_LockMutex(ctx->mutex);
        if (rc != 0) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_RNG, "wc_LockMutex", rc);
            ok = 0;
        }
    }
#endif

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Unlock the DRBG context object.
 *
 * @param [in, out] ctx  DRBG context object.
 * @return  1 on success.
 */
static int wp_drbg_unlock(wp_DrbgCtx* ctx)
{
    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_drbg_unlock");

#ifndef WP_SINGLE_THREADED
    if (ctx->mutex != NULL) {
       wc_UnLockMutex(ctx->mutex);
    }
#endif
    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

/**
 * Return an array of supported gettable parameters for the DRBG context object.
 *
 * @param [in] ctx      DRBG context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_drbg_gettable_ctx_params(wp_DrbgCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported gettable parameters for DRBG context.
     */
    static const OSSL_PARAM wp_supported_gettable_drbg_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_supported_gettable_drbg_ctx_params;
}

/**
 * Get the DRBG context parameters.
 *
 * @param [in]      ctx     DRBG context object. Unused.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_drbg_get_ctx_params(wp_DrbgCtx* ctx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_drbg_get_ctx_params");

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, WP_DRBG_MAX_REQUESTS))) {
        ok = 0;
    }
    if (ok) {
        int state = EVP_RAND_STATE_READY;

        if (ctx->rng == NULL) {
            state = EVP_RAND_STATE_UNINITIALISED;
        }
    #ifndef WP_HAVE_DRBG_RESEED
        /* Failed reseed re-instantiation left the DRBG de-instantiated. */
        else if (ctx->rngError) {
            state = EVP_RAND_STATE_ERROR;
        }
    #endif

        p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, state))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return an array of supported settable parameters for the DRBG context.
 *
 * @param [in] ctx      DRBG context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_drbg_settable_ctx_params(wp_DrbgCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported settable parameters for DRBG context.
     */
    static const OSSL_PARAM wp_supported_settable_ctx_params[] = {
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_supported_settable_ctx_params;
}

/**
 * Sets the parameters into the DRBG context object.
 *
 * @param [in] ctx     DRBG context object. Unused.
 * @param [in] params  Array of parameters and values. Unused.
 * @return  1 on success.
 */
static int wp_drbg_set_ctx_params(wp_DrbgCtx* ctx, const OSSL_PARAM params[])
{
    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_drbg_set_ctx_params");

    (void)ctx;
    (void)params;
    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

/**
 * Verify the zeroization of the DRBG components.
 *
 * @param [in] ctx      DRBG context object. Unused.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_drbg_verify_zeroization(wp_DrbgCtx* ctx)
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_drbg_verify_zeroization");

    /* After uninstantiate, ctx->rng is freed (with internal state zeroized
     * by wolfSSL) and set to NULL. Verify that cleanup occurred. */
    ok = (ctx->rng == NULL);

    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get secure seed.
 *
 * @param [in, out] ctx                    DRBG context object.
 * @param [out]     pSeed                  Handle to seed buffer.
 * @param [in]      entropy                Number of bits of required in seed.
 * @param [in]      minLen                 Minimum length of buffer to create in bytes.
 * @param [in]      maxLen                 Maximum length of buffer to create in bytes.
 * @param [in]      prediction_resistance  Prediction resistance required.
 * @param [in]      addIn                  Additional input to seed with.
 * @param [in]      addInLen               Length of additional input.
 * @return  Number of bytes of seed on success.
 * @return  0 on failure.
 */
static size_t wp_drbg_get_seed(wp_DrbgCtx* ctx, unsigned char** pSeed,
    int entropy, size_t minLen, size_t maxLen, int prediction_resistance,
    const unsigned char* addIn, size_t addInLen)
{
    size_t ret = 0;
    int rc;
    unsigned char* buffer = NULL;

    WOLFPROV_ENTER(WP_LOG_COMP_RNG, "wp_drbg_get_seed");

    (void)entropy;
    (void)maxLen;
    (void)prediction_resistance;
    (void)addIn;
    (void)addInLen;

    if (ctx->rng == NULL) {
        WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG,
            "DRBG not instantiated");
        goto end;
    }
#ifndef WP_HAVE_DRBG_RESEED
    if (ctx->rngError) {
        WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RNG, "DRBG in error state");
        goto end;
    }
#endif

    buffer = OPENSSL_secure_malloc(minLen);
    if (buffer == NULL) {
        goto end;
    }

    if (minLen > 0xFFFFFFFFU) {
        OPENSSL_secure_free(buffer);
        goto end;
    }

    rc = wc_RNG_GenerateBlock(ctx->rng, buffer, (word32)minLen);
    if (rc != 0) {
        WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_RNG,
            "wc_RNG_GenerateBlock", rc);
        OPENSSL_secure_free(buffer);
        goto end;
    }

    *pSeed = buffer;
    ret = minLen;

end:
    WOLFPROV_LEAVE(WP_LOG_COMP_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        ret > 0);
    return ret;
}

/**
 * Securely zeroize and free the seed buffer.
 *
 * @param [in]      ctx      DRBG context object. Unused.
 * @param [in, out] seed     Seed to zeroize.
 * @param [in]      seedLen  Length of seed in bytes.
 */
static void wp_drbg_clear_seed(wp_DrbgCtx* ctx, unsigned char* seed,
    size_t seedLen)
{
    (void)ctx;
    OPENSSL_secure_clear_free(seed, seedLen);
}

/** Dispatch table for DRBG. */
const OSSL_DISPATCH wp_drbg_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX,              (DFUNC)wp_drbg_new                 },
    { OSSL_FUNC_RAND_FREECTX,             (DFUNC)wp_drbg_free                },
    { OSSL_FUNC_RAND_INSTANTIATE,         (DFUNC)wp_drbg_instantiate         },
    { OSSL_FUNC_RAND_UNINSTANTIATE,       (DFUNC)wp_drbg_uninstantiate       },
    { OSSL_FUNC_RAND_GENERATE,            (DFUNC)wp_drbg_generate            },
    { OSSL_FUNC_RAND_RESEED,              (DFUNC)wp_drbg_reseed              },
    { OSSL_FUNC_RAND_ENABLE_LOCKING,      (DFUNC)wp_drbg_enable_locking      },
    { OSSL_FUNC_RAND_LOCK,                (DFUNC)wp_drbg_lock                },
    { OSSL_FUNC_RAND_UNLOCK,              (DFUNC)wp_drbg_unlock              },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (DFUNC)wp_drbg_settable_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS,      (DFUNC)wp_drbg_set_ctx_params      },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (DFUNC)wp_drbg_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS,      (DFUNC)wp_drbg_get_ctx_params      },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION,  (DFUNC)wp_drbg_verify_zeroization  },
    { OSSL_FUNC_RAND_GET_SEED,            (DFUNC)wp_drbg_get_seed            },
    { OSSL_FUNC_RAND_CLEAR_SEED,          (DFUNC)wp_drbg_clear_seed          },
    { 0, NULL }
};


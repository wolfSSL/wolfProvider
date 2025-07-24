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
    /** wolfSSL random number generator. HASH DRBG implementation. */
    WC_RNG* rng;
#ifndef WP_SINGLE_THREADED
    /** Mutex for multithreading access to this DRBG context. */
    wolfSSL_Mutex* mutex;
#endif
} wp_DrbgCtx;


/**
 * Create a new DRBG context object.
 *
 * @param [in] provCtx  Provider context.
 * @return  DRBG object on success.
 * @return  NULL on failure.
 */
static wp_DrbgCtx* wp_drbg_new(WOLFPROV_CTX* provCtx)
{
    wp_DrbgCtx* ctx = NULL;

    (void)provCtx;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }

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
 * @return  0 on success.
 */
static int wp_drbg_instantiate(wp_DrbgCtx* ctx, unsigned int strength,
    int predResist, const unsigned char* pStr, size_t pStrLen,
    const OSSL_PARAM params[])
{
    int ok = 1;

    (void)predResist;
    (void)params;

    if (strength > WP_DRBG_STRENGTH) {
        ok = 0;
    }
    if (ok ) {
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
                OPENSSL_clear_free(ctx->rng, sizeof(*ctx->rng));
                ok = 0;
            }
        }
    #endif
    }

    WOLFPROV_LEAVE(WP_LOG_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Uninstatiate DRBG.
 *
 * @param [in, out] ct
 */
static int wp_drbg_uninstantiate(wp_DrbgCtx* ctx)
{
#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
    (void)wc_rng_free(ctx->rng);
#else
    wc_FreeRng(ctx->rng);
    OPENSSL_clear_free(ctx->rng, sizeof(*ctx->rng));
#endif
    ctx->rng = NULL;
    WOLFPROV_LEAVE(WP_LOG_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}


/**
 * Generate random data.
 *
 * @param [in, out] ctx         DRBG context object.
 * @param [in]      strength    Strength in bits required.
 * @param [in]      predResist  Prediction resistance required.
 * @param [in]      addIn       Additional input data to seed with.
 * @param [in]      addInLen    Length of additional input data in bytes.
 * @return  1 on success.
 * @return  0 on success.
 */
static int wp_drbg_generate(wp_DrbgCtx* ctx, unsigned char* out,
    size_t outLen, unsigned int strength, int predResist,
    const unsigned char* addIn, size_t addInLen)
{
    int ok = 1;
    int rc;

    (void)predResist;

    if (strength > WP_DRBG_STRENGTH) {
        ok = 0;
    }
#if 0
    if (ok && (addInLen > 0)) {
        rc = wc_RNG_DRBG_Reseed(ctx->rng, addIn, addInLen);
        if (rc != 0) {
            ok = 0;
        }
    }
#else
    (void)addIn;
    (void)addInLen;
#endif
    if (ok) {
        rc = wc_RNG_GenerateBlock(ctx->rng, out, (word32)outLen);
        if (rc != 0) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/* No usage of EVP_RAND_reseed seen in OpenSSL library. */
/**
 * Reseed DRBG.
 *
 * @param [in, out] ctx         DRBG context object.
 * @param [in]      predResist  Prediction resistance required.
 * @param [in]      entropy     Entropy data to reseed with.
 * @param [in]      entropyLen  Length of entropy data.
 * @param [in]      addIn       Additional input data to reseed with.
 * @param [in]      addInLen    Length of additional input data in bytes.
 * @param [in]      params      Other parameters.
 * @return  1 on success.
 * @return  0 on success.
 */
static int wp_drbg_reseed(wp_DrbgCtx* ctx, int predResist,
    const unsigned char* entropy, size_t entropyLen,
    const unsigned char* addIn, size_t addInLen)
{
    int ok = 1;

#if 0
    /* Calling Hash_DRBG_Instantiate would be better. */
    int rc;
    rc = wc_RNG_DRBG_Reseed(ctx->rng, entropy, entropyLen);
    if (rc != 0) {
        ok = 0;
    }
    if (ok && (addInLen > 0)) {
        rc = wc_RNG_DRBG_Reseed(ctx->rng, addIn, addInLen);
        if (rc != 0) {
            ok = 0;
        }
    }
#else
    (void)ctx;
    (void)entropy;
    (void)entropyLen;
    (void)addIn;
    (void)addInLen;
#endif

    (void)predResist;

    WOLFPROV_LEAVE(WP_LOG_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Create a lock object for this DRBG context object.
 *
 * @param [in, out] ctx  DRBG context object.
 * @return  1 on success.
 * @return  0 on success.
 */
static int wp_drbg_enable_locking(wp_DrbgCtx* ctx)
{
    int ok = 1;

#ifndef WP_SINGLE_THREADED
    if (ctx->mutex == NULL) {
        ctx->mutex = OPENSSL_malloc(sizeof(*ctx->mutex));
        if (ctx->mutex == NULL) {
            ok = 0;
        }
        if (ok) {
            int rc = wc_InitMutex(ctx->mutex);
            if (rc != 0) {
                OPENSSL_free(ctx->mutex);
                ok = 0;
            }
        }
    }
#endif

    WOLFPROV_LEAVE(WP_LOG_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Lock the DRBG context object.
 *
 * @param [in, out] ctx  DRBG context object.
 * @return  1 on success.
 * @return  0 on success.
 */
static int wp_drbg_lock(wp_DrbgCtx* ctx)
{
    int ok = 1;
#ifndef WP_SINGLE_THREADED
    int rc;

    if (ctx->mutex != NULL) {
        rc = wc_LockMutex(ctx->mutex);
        if (rc != 0) {
            ok = 0;
        }
    }
#endif

    WOLFPROV_LEAVE(WP_LOG_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
#ifndef WP_SINGLE_THREADED
    if (ctx->mutex != NULL) {
       wc_UnLockMutex(ctx->mutex);
    }
#endif
    WOLFPROV_LEAVE(WP_LOG_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
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

    (void)ctx;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, WP_DRBG_MAX_REQUESTS))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, EVP_RAND_STATE_READY))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
    (void)ctx;
    (void)params;
    WOLFPROV_LEAVE(WP_LOG_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

/**
 * Verify the zeroization of the DRBG components.
 *
 * @param [in] ctx      DRBG context object. Unused.
 * @return  1 on success.
 */
static int wp_drbg_verify_zeroization(wp_DrbgCtx* ctx)
{
    (void)ctx;
    WOLFPROV_LEAVE(WP_LOG_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

/**
 * Get secure seed.
 *
 * @param [in, out] ctx         DRBG context object.
 * @param [out]     pSeed       Handle to seed buffer.
 * @param [in]      entropy     Number of bits of required in seed.
 * @param [in]      minLen      Minimum length of buffer to create in bytes.
 * @param [in]      minLen      Maximum length of buffer to create in bytes.
 * @param [in]      predResist  Prediction resistance required.
 * @param [in]      addIn       Additional input to seed with.
 * @param [in]      addInLen    Additional input to seed with.
 */
static size_t wp_drbg_get_seed(wp_DrbgCtx* ctx, unsigned char** pSeed,
    int entropy, size_t minLen, size_t maxLen, int prediction_resistance,
    const unsigned char* addIn, size_t addInLen)
{
    int ok = 1;
    int rc;
    unsigned char* buffer;

    (void)entropy;
    (void)maxLen;
    (void)prediction_resistance;

    buffer = OPENSSL_secure_malloc(minLen);
    if (buffer == NULL) {
        ok = 0;
    }
#if 0
    if (ok && (addInLen > 0)) {
        rc = wc_RNG_DRBG_Reseed(ctx->rng, addIn, addInLen);
        if (rc != 0) {
            ok = 0;
        }
    }
#else
    (void)addIn;
    (void)addInLen;
#endif
    if (ok) {
        rc = wc_RNG_GenerateBlock(ctx->rng, buffer, (word32)minLen);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        *pSeed = buffer;
    }
    if (!ok) {
        OPENSSL_secure_free(buffer);
    }

    WOLFPROV_LEAVE(WP_LOG_RNG, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
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


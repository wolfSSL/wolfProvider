/* wp_rsa_kem.c
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
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#ifdef WP_HAVE_RSA

/** Type of RSA KEM operation is Secret-Value Encapsulation. */
#define WP_RSA_KEM_OP_RSASVE    1


/**
 * RSA KEM context.
 *
 * Used to store provider context, key, operation type and instantiated RNG.
 */
typedef struct wp_RsaKemCtx {
    /** wolfProvider context object. */
    WOLFPROV_CTX* provCtx;

    /** wolfProvider RSA object. */
    wp_Rsa* rsa;
    /** wolfSSL random number generator for use during encapsulation. */
    WC_RNG rng;

    /** Type of pperation being performed. */
    int op;
} wp_RsaKemCtx;


/* Prototype for wp_rsakem_init() to use.  */
static int wp_rsakem_set_ctx_params(wp_RsaKemCtx* ctx,
    const OSSL_PARAM params[]);


/**
 * Create a new RSA KEM context object.
 *
 * @param [in] provCtx    wolfProvider context object.
 * @return  NULL on failure.
 * @return  RSA asymmetric cipher context object on success.
 */
static wp_RsaKemCtx* wp_rsakem_ctx_new(WOLFPROV_CTX* provCtx)
{
    wp_RsaKemCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
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
 * Free an RSA KEM context object.
 *
 * @param [in, out] ctx  RSA KEM context object. May be NULL.
 */
static void wp_rsakem_ctx_free(wp_RsaKemCtx* ctx)
{
    if (ctx != NULL) {
        wc_FreeRng(&ctx->rng);
        wp_rsa_free(ctx->rsa);
        OPENSSL_free(ctx);
    }
}

/**
 * Duplicate the RSA KEM context object.
 *
 * @param [in] srcCtx  RSA KEM context object.
 * @retturn  NULL on failure.
 * @return   RSA KEM context object on success.
 */
static wp_RsaKemCtx* wp_rsakem_ctx_dup(wp_RsaKemCtx* srcCtx)
{
    wp_RsaKemCtx* dstCtx = NULL;

    if (wolfssl_prov_is_running()) {
        int ok = 1;

        dstCtx = wp_rsakem_ctx_new(srcCtx->provCtx);
        if (dstCtx == NULL) {
            ok = 0;
        }

        if (ok && (!wp_rsa_up_ref(srcCtx->rsa))) {
            ok = 0;
        }
        if (ok) {
            dstCtx->rsa          = srcCtx->rsa;
            dstCtx->op           = srcCtx->op;
        }

        if (!ok) {
            wp_rsakem_ctx_free(dstCtx);
            dstCtx = NULL;
        }
    }

    return dstCtx;
}

/**
 * Initialize RSA KEM context object for encapsulation/decapsulation.
 *
 * @param [in, out] ctx        RSA KEM context object.
 * @param [in]      rsa        RSA key object.
 * @param [in]      params     Parameters to initialize with.
 * @param [in]      operation  Type of operation to perform.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsakem_init(wp_RsaKemCtx* ctx, wp_Rsa* rsa,
    const OSSL_PARAM params[], int operation)
{
    int ok = 1;

    /* TODO: check key type and size with operation. */
    (void)operation;

    if (rsa != ctx->rsa) {
        wp_rsa_free(ctx->rsa);
        ctx->rsa = NULL;
        if (!wp_rsa_up_ref(rsa)) {
            ok = 0;
        }
    }
    if (ok) {
        ctx->rsa = rsa;
    }

    return wp_rsakem_set_ctx_params(ctx, params);
}

/**
 * Initialize RSA KEM context object for encapsulation.
 *
 * @param [in, out] ctx     RSA KEM context object.
 * @param [in]      rsa     RSA key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsakem_encapsulate_init(wp_RsaKemCtx* ctx, wp_Rsa* rsa,
    const OSSL_PARAM params[])
{
    return wp_rsakem_init(ctx, rsa, params, EVP_PKEY_OP_ENCAPSULATE);
}

/**
 * Initialize RSA KEM context object for decapsulation.
 *
 * @param [in, out] ctx     RSA KEM context object.
 * @param [in]      rsa     RSA key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsakem_decapsulate_init(wp_RsaKemCtx* ctx, wp_Rsa* rsa,
    const OSSL_PARAM params[])
{
    return wp_rsakem_init(ctx, rsa, params, EVP_PKEY_OP_DECAPSULATE);
}

static int wp_mp_rand(mp_int* a, int digits, WC_RNG* rng)
{
    int cnt = digits * sizeof(mp_digit);

    a->used = digits;

    return wc_RNG_GenerateBlock(rng, (byte*)a->dp, cnt);
}

/**
 * Generate a number between 2 and n-2 (1 < r < n-1).
 *
 * NIST.SP.800-56Br2
 * 7.2.1.2 RSASVE Generate Operation (RSASVE.GENERATE).
 *
 * @param [in]  ctx  RSA KEM context object.
 * @param [out] out  Buffer holding random number.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsasve_gen_rand_bytes(wp_RsaKemCtx* ctx, unsigned char* out)
{
    int ok = 1;
    int rc;
    mp_int r;
    mp_int mod;
    RsaKey* key = wp_rsa_get_key(ctx->rsa);

    rc = mp_init_multi(&r, &mod, NULL, NULL, NULL, NULL);
    if (rc != 0) {
        ok = 0;
    }
    if (ok) {
        /* mod = n - 3 */
        rc = mp_sub_d(&key->n, 3, &mod);
        if (rc != 0) {
            ok = 0;
        }
    }
    while (ok) {
        /* r = random number with all words filled. */
        rc = wp_mp_rand(&r, mod.used, &ctx->rng);
        if (rc != 0) {
            ok = 0;
        }
        /* Done when random is less than modulus. */
        if (ok && (mp_cmp(&r, &mod) == MP_LT)) {
            break;
        }
    }
    if (ok) {
        /* r in range 0..n-4. Add 2 and r in range 2..n-2. */
        rc = mp_add_d(&r, 2, &r);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        /* Encode random number as a zero padded, big-endian array of bytes. */
        rc = mp_to_unsigned_bin_len(&r, out, mp_unsigned_bin_size(&key->n));
        if (rc != 0) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Generate a secret value and corresponding ciphertext (encapsulate).
 *
 * NIST.SP.800-56Br2
 * 7.2.1.2 RSASVE Generate Operation (RSASVE.GENERATE).
 *
 * @param [in]  ctx        RSA KEM context object.
 * @param [out] out        Buffer to hold encapsulated random number.
 * @param [out] outLen     Length of encapsulated data in bytes.
 * @param [out] secret     Buffer to hold secret.
 * @param [out] secretLen  Length of secret data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsasve_generate(wp_RsaKemCtx* ctx, unsigned char* out,
    size_t* outLen, unsigned char* secret, size_t* secretLen)
{
    int ok = 1;
    word32 nLen;
    word32 oLen;
    RsaKey* rsa = NULL;

    if ((out == NULL) && (outLen == NULL) && (secretLen == NULL)) {
        ok = 0;
    }

    if (ok) {
        rsa = wp_rsa_get_key(ctx->rsa);
        /* Step 1: nLen = CEIL(len(n)/8) */
        nLen = wc_RsaEncryptSize(rsa);
        if (nLen == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            ok = 0;
        }
    }

    /* Step 2: Generate a random byte string z of nLen bytes, 1 < z < n - 1 */
    if (ok && (out != NULL) && (!wp_rsasve_gen_rand_bytes(ctx, secret))) {
        ok = 0;
    }
    if (ok && (out != NULL)) {
        /* Step 3: out = RSAEP((n,e), z) */
        int rc;

        oLen = nLen;
        rc = wc_RsaDirect(secret, nLen, out, &oLen, rsa, RSA_PUBLIC_ENCRYPT,
            &ctx->rng);
        if (rc < 0) {
            OPENSSL_cleanse(secret, nLen);
            ok = 0;
        }
        /* Front pad output with zeros if required. */
        if (ok && (oLen < nLen)) {
            word32 padLen = nLen - oLen;
            XMEMMOVE(out + padLen, out, oLen);
            XMEMSET(out, 0, padLen);
        }
    }

    if (ok) {
        /* Return lengths if asked - all numbers front padded with zeros. */
        if (outLen != NULL) {
            *outLen = nLen;
        }
        if (secretLen != NULL) {
            *secretLen = nLen;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encapsulation for RSA KEM.
 *
 * @param [in]  ctx        RSA KEM context object.
 * @param [out] out        Buffer to hold encapsulated random number.
 * @param [out] outLen     Length of encapsulated data in bytes.
 * @param [out] secret     Buffer to hold secret.
 * @param [out] secretLen  Length of secret data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsakem_encapsulate(wp_RsaKemCtx* ctx, unsigned char* out,
    size_t* outlen, unsigned char* secret, size_t* secretlen)
{
    int ok;

    switch (ctx->op) {
        case WP_RSA_KEM_OP_RSASVE:
            ok = wp_rsasve_generate(ctx, out, outlen, secret, secretlen);
            break;
        default:
            /* As per OpenSSL. */
            ok = -2;
            break;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Recover the secret from the encapsulated data (decapsulate).
 *
 * NIST.SP.800-56Br2
 * 7.2.1.3 RSASVE Recovery Operation (RSASVE.RECOVER).
 *
 * @param [in]  ctx        RSA KEM context object.
 * @param [out] out        Buffer to hold secret.
 * @param [out] outLen     Length of secret in bytes.
 * @param [out] in         Buffer holding encapsulated secret.
 * @param [out] secretLen  Length of encapsulated data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsasve_recover(wp_RsaKemCtx* ctx, unsigned char* out,
    size_t* outLen, const unsigned char* in, size_t inLen)
{
    int ok = 1;
    word32 nLen;
    RsaKey* rsa = wp_rsa_get_key(ctx->rsa);

    /* Step 1: get the byte length of n */
    nLen = wc_RsaEncryptSize(rsa);
    if (nLen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        ok = 0;
    }

    /* Step 2: check the input ciphertext 'inlen' matches the nlen */
    if (ok && (out != NULL) && (inLen != nLen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        ok = 0;
    }
    /* Step 3: out = RSADP((n,d), in) */
    if (ok && (out != NULL)) {
        word32 oLen = nLen;
        int rc;

        PRIVATE_KEY_UNLOCK();
        rc = wc_RsaDirect((byte*)in, (word32)inLen, out, &oLen, rsa,
            RSA_PRIVATE_DECRYPT, &ctx->rng);
        PRIVATE_KEY_LOCK();
        if (rc < 0) {
            ok = 0;
        }
        /* Front pad output with zeros if required. */
        if (ok && (oLen < nLen)) {
            word32 padLen = nLen - oLen;
            XMEMMOVE(out + padLen, out, oLen);
            XMEMSET(out, 0, padLen);
        }
    }
    if (ok && (outLen != NULL)) {
        *outLen = nLen;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decapsulation for RSA KEM.
 *
 * @param [in]  ctx        RSA KEM context object.
 * @param [out] out        Buffer to hold secret.
 * @param [out] outLen     Length of secret in bytes.
 * @param [out] in         Buffer holding encapsulated secret.
 * @param [out] secretLen  Length of encapsulated data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsakem_decapsulate(wp_RsaKemCtx* ctx, unsigned char* out,
    size_t* outlen, const unsigned char* in, size_t inlen)
{
    int ok;

    switch (ctx->op) {
        case WP_RSA_KEM_OP_RSASVE:
            ok = wp_rsasve_recover(ctx, out, outlen, in, inlen);
            break;
        default:
            /* As per OpenSSL. */
            ok = -2;
            break;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Put data from RSA KEM context object into parameter objects.
 *
 * No supported parameters.
 *
 * @param [in] ctx     RSA KEM context object.
 * @param [in] params  Array of parameter objects. Unused.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsakem_get_ctx_params(wp_RsaKemCtx* ctx, OSSL_PARAM* params)
{
    (void)params;
    return ctx != NULL;
}

/**
 * Returns an array of RSA KEM context parameters that can be retrieved.
 *
 * No parameters supported.
 *
 * @param [in] ctx      RSA KEM context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM *wp_rsakem_gettable_ctx_params(wp_RsaKemCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_rsakem_supported_gettable_ctx_params[] = {
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_rsakem_supported_gettable_ctx_params;
}

/**
 * Sets the parameters to use into RSA KEM context object.
 *
 * @param [in, out] ctx     RSA KEM context object.
 * @param [in]      params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsakem_set_ctx_params(wp_RsaKemCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;
    const char* op = NULL;

    /* Type of RSA KEM operation - only RSASVE supported. */
    if (!wp_params_get_utf8_string_ptr(params, OSSL_KEM_PARAM_OPERATION,
        &op)) {
        ok = 0;
    }
    if (ok && (op != NULL)) {
        if (XSTRNCMP(OSSL_KEM_PARAM_OPERATION_RSASVE, op,
                sizeof(OSSL_KEM_PARAM_OPERATION_RSASVE) - 1) == 0) {
            ctx->op = WP_RSA_KEM_OP_RSASVE;
        }
        else {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns an array of RSA KEM context parameters that can be set.
 *
 * @param [in] ctx      RSA KEM context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM *wp_rsakem_settable_ctx_params(wp_RsaKemCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_rsakem_supported_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_rsakem_supported_settable_ctx_params;
}


/** Dspatch table for RSA KEM. */
const OSSL_DISPATCH wp_rsa_asym_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX,              (DFUNC)wp_rsakem_ctx_new             },
    { OSSL_FUNC_KEM_FREECTX,             (DFUNC)wp_rsakem_ctx_free            },
    { OSSL_FUNC_KEM_DUPCTX,              (DFUNC)wp_rsakem_ctx_dup             },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,    (DFUNC)wp_rsakem_encapsulate_init    },
    { OSSL_FUNC_KEM_ENCAPSULATE,         (DFUNC)wp_rsakem_encapsulate         },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,    (DFUNC)wp_rsakem_decapsulate_init    },
    { OSSL_FUNC_KEM_DECAPSULATE,         (DFUNC)wp_rsakem_decapsulate         },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS,      (DFUNC)wp_rsakem_get_ctx_params      },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (DFUNC)wp_rsakem_gettable_ctx_params },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,      (DFUNC)wp_rsakem_set_ctx_params      },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (DFUNC)wp_rsakem_settable_ctx_params },
    { 0, NULL }
};

#endif /* WP_HAVE_RSA */


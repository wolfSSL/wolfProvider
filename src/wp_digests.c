/* wp_digests.c
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

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

/** Flag indicates the algorithm is an eXtendable Output Function. */
#define WP_DIGEST_FLAG_XOF             0x0001
/** Flag indicates the algorithm doesn't have a parameter in the ASN.1 alg id.
 */
#define WP_DIGEST_FLAG_ALGID_ABSENT    0x0002


/** Implement a function for algorithm that gets the parameters. */
#define IMPLEMENT_DIGEST_GET_PARAM(name, blkSize, dgstSize, flags)             \
/**                                                                            \
 * Get the parameters for the algorithm.                                       \
 *                                                                             \
 * @param [in, out] params  Parameters to be looked-up.                        \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int name##_get_params(OSSL_PARAM params[])                              \
{                                                                              \
    return wp_digest_get_params(params, blkSize, dgstSize, flags);             \
}

/** Implement creating a new digest object. */
#define IMPLEMENT_DIGEST_NEWCTX(name, CTX)                                     \
/**                                                                            \
 * Create a new digest context object.                                         \
 *                                                                             \
 * @param [in] provCtx  Provider context.                                      \
 * @return NULL on error.                                                      \
 * @return Digest context object on success.                                   \
 */                                                                            \
static CTX* name##_newctx(WOLFPROV_CTX* provCtx)                               \
{                                                                              \
    CTX* ctx = NULL;                                                           \
    (void)provCtx;                                                             \
    if (wolfssl_prov_is_running()) {                                           \
        ctx = OPENSSL_zalloc(sizeof(CTX));                                     \
    }                                                                          \
    return ctx;                                                                \
}

/** Implement disposing of a digest object. */
#define IMPLEMENT_DIGEST_FREECTX(name, CTX, free)                              \
/**                                                                            \
 * Free the digest context object.                                             \
 *                                                                             \
 * Calls the wolfSSL digest object free function.                              \
 * Frees the pointer.                                                          \
 *                                                                             \
 * @param [in, out] ctx  Digest context object.                                \
 */                                                                            \
static void name##_freectx(CTX* ctx)                                           \
{                                                                              \
    free(ctx);                                                                 \
    OPENSSL_free(ctx);                                                         \
}

/** Implement duplicating a digest object. */
#define IMPLEMENT_DIGEST_DUPCTX(name, CTX, copy)                               \
/**                                                                            \
 * Duplicates a digest context object.                                         \
 *                                                                             \
 * @param [in] src  Digest context object.                                     \
 * @return  NULL on error.                                                     \
 * @return  Digest context object on success.                                  \
 */                                                                            \
static CTX* name##_dupctx(CTX* src)                                            \
{                                                                              \
    CTX* dst = NULL;                                                           \
    if (wolfssl_prov_is_running()) {                                           \
        dst = OPENSSL_malloc(sizeof(*src));                                    \
    }                                                                          \
    if (dst != NULL) {                                                         \
        int rc;                                                                \
        rc = copy(src, dst);                                                   \
        if (rc != 0) {                                                         \
            OPENSSL_free(dst);                                                 \
            dst = NULL;                                                        \
        }                                                                      \
    }                                                                          \
    return dst;                                                                \
}

/** Implement initialization of a digest object. */
#define IMPLEMENT_DIGEST_INIT(name, CTX, init)                                 \
/**                                                                            \
 * Initialize the digest context object.                                       \
 *                                                                             \
 * @param [in, out] ctx     Digest context object.                             \
 * @param [in, out] params  Parameters to be set. Unused.                      \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int name##_init(CTX* ctx, const OSSL_PARAM params[])                    \
{                                                                              \
    int ok = 1;                                                                \
    (void)params;                                                              \
    if (!wolfssl_prov_is_running()) {                                          \
        ok = 0;                                                                \
    }                                                                          \
    if (ok) {                                                                  \
        int rc = init(ctx, NULL, -1);                                          \
        if (rc != 0) {                                                         \
            ok = 0;                                                            \
        }                                                                      \
    }                                                                          \
    WOLFPROV_LEAVE(WP_LOG_DIGEST, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);\
    return ok;                                                                 \
}                                                                              \

/** Implement updating a digest object with data. */
#define IMPLEMENT_DIGEST_UPDATE(name, CTX, upd)                                \
/**                                                                            \
 * Update the digest context object with data.                                 \
 *                                                                             \
 * @param [in, out] ctx    Digest context object.                              \
 * @param [in]      in     Data to be digested.                                \
 * @param [in]      inLen  Length of data in bytes.                            \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int name##_update(void* ctx, const unsigned char* in, size_t inLen)     \
{                                                                              \
    int ok = 1;                                                                \
    int rc = upd(ctx, in, (word32)inLen);                                      \
    if (rc != 0) {                                                             \
        ok = 0;                                                                \
    }                                                                          \
    WOLFPROV_LEAVE(WP_LOG_DIGEST, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);\
    return ok;                                                                 \
}

/** Implement finalizing a digest object to produce hash result. */
#define IMPLEMENT_DIGEST_FINAL(name, CTX, dgstSize, fin)                       \
/**                                                                            \
 * Finalize the digest operation.                                              \
 *                                                                             \
 * @param [in, out] ctx      Digest context object.                            \
 * @param [out]     out      Digest result.                                    \
 * @param [out]     outLen   Length of digest in bytes.                        \
 * @param [in]      outSize  Size of buffer in bytes.                          \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int name##_final(void* ctx, unsigned char* out, size_t* outLen,         \
    size_t outSize)                                                            \
{                                                                              \
    int ok = 1;                                                                \
    if (!wolfssl_prov_is_running()) {                                          \
        ok = 0;                                                                \
    }                                                                          \
    if (ok && (outSize < dgstSize)) {                                          \
        ok = 0;                                                                \
    }                                                                          \
    if (ok) {                                                                  \
        int rc = fin(ctx, out);                                                \
        if (rc != 0) {                                                         \
            ok = 0;                                                            \
        }                                                                      \
        else {                                                                 \
            *outLen = dgstSize;                                                \
        }                                                                      \
    }                                                                          \
    WOLFPROV_LEAVE(WP_LOG_DIGEST, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);\
    return ok;                                                                 \
}


/**
 * Implement the digest functions for an algorithm.
 * Also define the dispatch table for the functions.
 */
#define IMPLEMENT_DIGEST(name, CTX, blkSize, dgstSize, flags,                  \
                         init, upd, fin, copy, free)                           \
IMPLEMENT_DIGEST_NEWCTX(name, CTX)                                             \
IMPLEMENT_DIGEST_INIT(name, CTX, init)                                         \
IMPLEMENT_DIGEST_UPDATE(name, CTX, upd)                                        \
IMPLEMENT_DIGEST_FINAL(name, CTX, dgstSize, fin)                               \
IMPLEMENT_DIGEST_FREECTX(name, CTX, free)                                      \
IMPLEMENT_DIGEST_DUPCTX(name, CTX, copy)                                       \
IMPLEMENT_DIGEST_GET_PARAM(name, blkSize, dgstSize, flags)                     \
/** Dispatch table for digest algorithms. */                                   \
const OSSL_DISPATCH name##_functions[] = {                                     \
    { OSSL_FUNC_DIGEST_NEWCTX,          (DFUNC)name##_newctx                }, \
    { OSSL_FUNC_DIGEST_INIT,            (DFUNC)name##_init                  }, \
    { OSSL_FUNC_DIGEST_UPDATE,          (DFUNC)name##_update                }, \
    { OSSL_FUNC_DIGEST_FINAL,           (DFUNC)name##_final                 }, \
    { OSSL_FUNC_DIGEST_FREECTX,         (DFUNC)name##_freectx               }, \
    { OSSL_FUNC_DIGEST_DUPCTX,          (DFUNC)name##_dupctx                }, \
    { OSSL_FUNC_DIGEST_GET_PARAMS,      (DFUNC)name##_get_params            }, \
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (DFUNC)wp_digest_gettable_params    }, \
    { 0,                                NULL                                }  \
};


/**
 * Get parameters of a digest algorithm.
 *
 * @param [in, out] params     Parameters to be looked-up.
 * @param [in]      blkSize    Block size for the algorithm.
 * @param [in]      paramSize  Digest size for the algorithm.
 * @param [in]      flags      Flags of the algorithm.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_digest_get_params(OSSL_PARAM params[], size_t blkSize,
    size_t paramSize, unsigned long flags)
{
    OSSL_PARAM* p = NULL;
    int ok = 1;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, blkSize))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, paramSize))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p,
                (flags & WP_DIGEST_FLAG_XOF) != 0))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
        if (p != NULL && !OSSL_PARAM_set_int(p,
                (flags & WP_DIGEST_FLAG_ALGID_ABSENT) != 0)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_DIGEST, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the table of supported parameters for digests.
 *
 * @param [in] provCtx  Provider context.
 * @return Table of supported parameters.
 */
static const OSSL_PARAM* wp_digest_gettable_params(void* provCtx)
{
    /** Table of supported parameters. */
    static const OSSL_PARAM wp_digest_supported_gettable_params[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
        OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
        OSSL_PARAM_END
    };

    (void)provCtx;
    return wp_digest_supported_gettable_params;
}

/*******************************************************************************
 * MD5
 ******************************************************************************/

#ifdef WP_HAVE_MD5
IMPLEMENT_DIGEST(wp_md5, wc_Md5,
                 WC_MD5_BLOCK_SIZE, WC_MD5_DIGEST_SIZE,
                 0,
                 wc_InitMd5_ex, wc_Md5Update, wc_Md5Final,
                 wc_Md5Copy, wc_Md5Free)
#endif

/*******************************************************************************
 * SHA1-MD5
 ******************************************************************************/

#ifdef WP_HAVE_MD5_SHA1
/**
 * Combined MD5 and SHA-1 digest.
 */
typedef struct wp_Md5Sha {
    /** MD5 object from wolfSSL. */
    wc_Md5 md5;
    /** SHA-1 object from wolfSSL. */
    wc_Sha sha;
} wp_Md5Sha;

/**
 * MD5 and SHA-1 combo initialization implementation in wolfSSL form.
 *
 * @param [in, out] dgst   Digest context object.
 * @param [in]      heap   Heap hint.
 * @param [in]      devId  Device identifier.
 * @return  0 on success.
 * @return  -ve on error.
 */
static int wp_InitMd5Sha_ex(wp_Md5Sha* dgst, void* heap, int devId)
{
    int rc;

    rc = wc_InitMd5_ex(&dgst->md5, heap, devId);
    if (rc == 0) {
        rc = wc_InitSha_ex(&dgst->sha, heap, devId);
    }

    return rc;
}

/**
 * MD5 and SHA-1 combo update implementation in wolfSSL form.
 *
 * @param [in, out] dgst   Digest context object.
 * @param [in]      data   Data to digest.
 * @param [in]      len    Length of data in bytes.
 * @return  0 on success.
 * @return  -ve on error.
 */
static int wp_Md5ShaUpdate(wp_Md5Sha* dgst, const byte* data, word32 len)
{
    int rc;

    rc = wc_Md5Update(&dgst->md5, data, len);
    if (rc == 0) {
        rc = wc_ShaUpdate(&dgst->sha, data, len);
    }

    return rc;
}

/**
 * MD5 and SHA-1 combo finalization implementation in wolfSSL form.
 *
 * @param [in, out] dgst   Digest context object.
 * @param [in]      data   Data to digest.
 * @param [in]      len    Length of data in bytes.
 * @return  0 on success.
 * @return  -ve on error.
 */
static int wp_Md5ShaFinal(wp_Md5Sha* dgst, byte* hash)
{
    int rc;

    rc = wc_Md5Final(&dgst->md5, hash);
    if (rc == 0) {
        rc = wc_ShaFinal(&dgst->sha, hash + WC_MD5_DIGEST_SIZE);
    }

    return rc;
}

/**
 * MD5 and SHA-1 combo copy implementation in wolfSSL form.
 *
 * @param [in]      src  Digest context object.
 * @param [in, out] dst  Digest context object.
 * @return  0 on success.
 * @return  -ve on error.
 */
static int wp_Md5ShaCopy(wp_Md5Sha* src, wp_Md5Sha* dst)
{
    int rc;

    rc = wc_Md5Copy(&src->md5, &dst->md5);
    if (rc == 0) {
        rc = wc_ShaCopy(&src->sha, &dst->sha);
    }

    return rc;
}

/**
 * MD5 and SHA-1 combo free implementation in wolfSSL form.
 *
 * @param [in, out] dgst  Digest context object.
 * @return  0 on success.
 * @return  -ve on error.
 */
static void wp_Md5ShaFree(wp_Md5Sha* d)
{
    if (d != NULL) {
        wc_Md5Free(&d->md5);
        wc_ShaFree(&d->sha);
    }
}

IMPLEMENT_DIGEST(wp_md5_sha1, wp_Md5Sha,
                 WC_MD5_BLOCK_SIZE, WC_MD5_DIGEST_SIZE + WC_SHA_DIGEST_SIZE,
                 0,
                 wp_InitMd5Sha_ex, wp_Md5ShaUpdate, wp_Md5ShaFinal,
                 wp_Md5ShaCopy, wp_Md5ShaFree)
#endif

/*******************************************************************************
 * SHA-1
 ******************************************************************************/

#ifdef WP_HAVE_SHA1
IMPLEMENT_DIGEST(wp_sha1, wc_Sha,
                 WC_SHA_BLOCK_SIZE, WC_SHA_DIGEST_SIZE,
                 0,
                 wc_InitSha_ex, wc_ShaUpdate, wc_ShaFinal,
                 wc_ShaCopy, wc_ShaFree)
#endif

/*******************************************************************************
 * SHA-2
 ******************************************************************************/

/** All SHA-2 algorithms have no ASN.1 algorithm id parameter. */
#define WP_SHA2_FLAGS   WP_DIGEST_FLAG_ALGID_ABSENT

/* All the SHA-2 implementations. */
#ifdef WP_HAVE_SHA224
IMPLEMENT_DIGEST(wp_sha224, wc_Sha224,
                 WC_SHA224_BLOCK_SIZE, WC_SHA224_DIGEST_SIZE,
                 WP_SHA2_FLAGS,
                 wc_InitSha224_ex, wc_Sha224Update, wc_Sha224Final,
                 wc_Sha224Copy, wc_Sha224Free)
#endif /* WP_HAVE_SHA224 */

#ifdef WP_HAVE_SHA256
IMPLEMENT_DIGEST(wp_sha256, wc_Sha256,
                 WC_SHA256_BLOCK_SIZE, WC_SHA256_DIGEST_SIZE,
                 WP_SHA2_FLAGS,
                 wc_InitSha256_ex, wc_Sha256Update, wc_Sha256Final,
                 wc_Sha256Copy, wc_Sha256Free)
#endif /* WP_HAVE_SHA256 */

#ifdef WP_HAVE_SHA384
IMPLEMENT_DIGEST(wp_sha384, wc_Sha384,
                 WC_SHA384_BLOCK_SIZE, WC_SHA384_DIGEST_SIZE,
                 WP_SHA2_FLAGS,
                 wc_InitSha384_ex, wc_Sha384Update, wc_Sha384Final,
                 wc_Sha384Copy, wc_Sha384Free)
#endif /* WP_HAVE_SHA384 */

#ifdef WP_HAVE_SHA512
IMPLEMENT_DIGEST(wp_sha512, wc_Sha512,
                 WC_SHA512_BLOCK_SIZE, WC_SHA512_DIGEST_SIZE,
                 WP_SHA2_FLAGS,
                 wc_InitSha512_ex, wc_Sha512Update, wc_Sha512Final,
                 wc_Sha512Copy, wc_Sha512Free)

#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
#if !defined(WOLFSSL_NOSHA512_224) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
IMPLEMENT_DIGEST(wp_sha512_224, wc_Sha512_224,
                 WC_SHA512_224_BLOCK_SIZE, WC_SHA512_224_DIGEST_SIZE,
                 WP_SHA2_FLAGS,
                 wc_InitSha512_224_ex, wc_Sha512_224Update, wc_Sha512_224Final,
                 wc_Sha512_224Copy, wc_Sha512_224Free)
#endif /* WOLFSSL_NOSHA512_224 */

#if !defined(WOLFSSL_NOSHA512_256) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
IMPLEMENT_DIGEST(wp_sha512_256, wc_Sha512_256,
                 WC_SHA512_256_BLOCK_SIZE, WC_SHA512_256_DIGEST_SIZE,
                 WP_SHA2_FLAGS,
                 wc_InitSha512_256_ex, wc_Sha512_256Update, wc_Sha512_256Final,
                 wc_Sha512_256Copy, wc_Sha512_256Free)
#endif /* WOLFSSL_NOSHA512_256 */
#endif
#endif /* WP_HAVE_SHA512 */


/*******************************************************************************
 * SHA-3
 ******************************************************************************/

/** All SHA-3 algorithms have no ASN.1 algorithm id parameter. */
#define WP_SHA3_FLAGS   WP_DIGEST_FLAG_ALGID_ABSENT

#ifdef WP_HAVE_SHA3
/* All the SHA-3 implementations. */
IMPLEMENT_DIGEST(wp_sha3_224, wc_Sha3,
                 WC_SHA3_224_BLOCK_SIZE, WC_SHA3_224_DIGEST_SIZE,
                 WP_SHA3_FLAGS,
                 wc_InitSha3_224, wc_Sha3_224_Update, wc_Sha3_224_Final,
                 wc_Sha3_224_Copy, wc_Sha3_224_Free)

IMPLEMENT_DIGEST(wp_sha3_256, wc_Sha3,
                 WC_SHA3_256_BLOCK_SIZE, WC_SHA3_256_DIGEST_SIZE,
                 WP_SHA3_FLAGS,
                 wc_InitSha3_256, wc_Sha3_256_Update, wc_Sha3_256_Final,
                 wc_Sha3_256_Copy, wc_Sha3_256_Free)

IMPLEMENT_DIGEST(wp_sha3_384, wc_Sha3,
                 WC_SHA3_384_BLOCK_SIZE, WC_SHA3_384_DIGEST_SIZE,
                 WP_SHA3_FLAGS,
                 wc_InitSha3_384, wc_Sha3_384_Update, wc_Sha3_384_Final,
                 wc_Sha3_384_Copy, wc_Sha3_384_Free)

IMPLEMENT_DIGEST(wp_sha3_512, wc_Sha3,
                 WC_SHA3_512_BLOCK_SIZE, WC_SHA3_512_DIGEST_SIZE,
                 WP_SHA3_FLAGS,
                 wc_InitSha3_512, wc_Sha3_512_Update, wc_Sha3_512_Final,
                 wc_Sha3_512_Copy, wc_Sha3_512_Free)
#endif

/*******************************************************************************
 * XOF
 ******************************************************************************/

/** Implement initialization of an XOF object. */
#define IMPLEMENT_XOF_INIT(alg, name, CTX, init)                               \
/**                                                                            \
 * Initialize the XOF context object.                                          \
 *                                                                             \
 * @param [in]      ctx     XOF context object.                                \
 * @param [in, out] params  Parameters to be set.                              \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int name##_init(CTX* ctx, const OSSL_PARAM params[])                    \
{                                                                              \
    int ok = 1;                                                                \
    (void)params;                                                              \
    if (!wolfssl_prov_is_running()) {                                          \
        ok = 0;                                                                \
    }                                                                          \
    if (ok) {                                                                  \
        int rc = init(&ctx->obj, NULL, -1);                                    \
        if (rc != 0) {                                                         \
            ok = 0;                                                            \
        }                                                                      \
    }                                                                          \
    if (ok && (!wp_##alg##_set_ctx_params(ctx, params))) {                     \
        ok = 0;                                                                \
    }                                                                          \
    WOLFPROV_LEAVE(WP_LOG_DIGEST, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);\
    return ok;                                                                 \
}                                                                              \

/** Implement finalizing an XOF object to produce output. */
#define IMPLEMENT_XOF_FINAL(name, CTX, dgstSize, fin)                          \
/**                                                                            \
 * Finalize the XOF operation.                                                 \
 *                                                                             \
 * @param [in, out] ctx      XOF context object.                               \
 * @param [out]     out      Output buffer.                                    \
 * @param [out]     outLen   Length of output in bytes.                        \
 * @param [in]      outSize  Size of buffer in bytes.                          \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int name##_final(CTX* ctx, unsigned char* out, size_t* outLen,          \
    size_t outSize)                                                            \
{                                                                              \
    int ok = 1;                                                                \
    if (!wolfssl_prov_is_running()) {                                          \
        ok = 0;                                                                \
    }                                                                          \
    if (ok && (outSize < ctx->outLen)) {                                       \
        ok = 0;                                                                \
    }                                                                          \
    if (ok) {                                                                  \
        int rc = fin(&ctx->obj, out, (word32)ctx->outLen);                     \
        if (rc != 0) {                                                         \
            ok = 0;                                                            \
        }                                                                      \
        else {                                                                 \
           *outLen = ctx->outLen;                                             \
        }                                                                      \
    }                                                                          \
    WOLFPROV_LEAVE(WP_LOG_DIGEST, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);\
    return ok;                                                                 \
}

/** Implement disposing of an XOF object. */
#define IMPLEMENT_XOF_FREECTX(name, CTX, free)                                 \
/**                                                                            \
 * Free the XOF context object.                                                \
 *                                                                             \
 * Calls the wolfSSL XOF object free function.                                 \
 * Frees the pointer.                                                          \
 *                                                                             \
 * @param [in] ctx  XOF context object.                                        \
 */                                                                            \
static void name##_freectx(CTX* ctx)                                           \
{                                                                              \
    free(&ctx->obj);                                                           \
    OPENSSL_free(ctx);                                                         \
}

/** Implement duplicating an XOF object. */
#define IMPLEMENT_XOF_DUPCTX(name, CTX, copy)                                  \
/**                                                                            \
 * Duplicates an XOF context object.                                           \
 *                                                                             \
 * @param [in] src  XOF context object.                                        \
 * @return  NULL on error.                                                     \
 * @return  XOF context object on success.                                     \
 */                                                                            \
static CTX* name##_dupctx(CTX* src)                                            \
{                                                                              \
    CTX* dst = NULL;                                                           \
    if (wolfssl_prov_is_running()) {                                           \
        dst = OPENSSL_malloc(sizeof(*src));                                    \
    }                                                                          \
    if (dst != NULL) {                                                         \
        int rc;                                                                \
        rc = copy(&src->obj, &dst->obj);                                       \
        if (rc != 0) {                                                         \
            OPENSSL_free(dst);                                                 \
            dst = NULL;                                                        \
        }                                                                      \
        else {                                                                 \
            dst->outLen = src->outLen;                                         \
        }                                                                      \
    }                                                                          \
    return dst;                                                                \
}

/** Implement setting the context parameters. */
#define IMPLEMENT_XOF_SET_CTX_PARAMS(name, CTX)                                \
/**                                                                            \
 * Set the parameters into the context.                                        \
 *                                                                             \
 * @param [in, out] ctx     XOF context.                                       \
 * @param [in]      params  Parameters to be set.                              \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int name##_set_ctx_params(CTX* ctx, const OSSL_PARAM params[])          \
{                                                                              \
    int ok = 1;                                                                \
    if (!wolfssl_prov_is_running()) {                                          \
        ok = 0;                                                                \
    }                                                                          \
    if (ok && (params != NULL) && (!wp_params_get_size_t(params,               \
                OSSL_DIGEST_PARAM_XOFLEN, &ctx->outLen))) {                    \
        ok = 0;                                                                \
    }                                                                          \
    WOLFPROV_LEAVE(WP_LOG_DIGEST, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);\
    return ok;                                                                 \
}


/**
 * Implement the XOF functions for an algorithm.
 * Also define the dispatch table for the functions.
 */
#define IMPLEMENT_XOF(alg, name, WC_CTX, CTX, blkSize, dgstSize, flags,        \
                      init, upd, fin, copy, free)                              \
IMPLEMENT_XOF_INIT(alg, name, CTX, init)                                       \
IMPLEMENT_DIGEST_UPDATE(name, WC_CTX, upd)                                     \
IMPLEMENT_XOF_FINAL(name, CTX, dgstSize, fin)                                  \
IMPLEMENT_XOF_FREECTX(name, CTX, free)                                         \
IMPLEMENT_XOF_DUPCTX(name, CTX, copy)                                          \
IMPLEMENT_DIGEST_GET_PARAM(name, blkSize, dgstSize, flags)                     \
/** Dispatch table for XOF algorithms. */                                      \
const OSSL_DISPATCH name##_functions[] = {                                     \
    { OSSL_FUNC_DIGEST_NEWCTX,            (DFUNC)wp_##alg##_newctx          }, \
    { OSSL_FUNC_DIGEST_INIT,              (DFUNC)name##_init                }, \
    { OSSL_FUNC_DIGEST_UPDATE,            (DFUNC)name##_update              }, \
    { OSSL_FUNC_DIGEST_FINAL,             (DFUNC)name##_final               }, \
    { OSSL_FUNC_DIGEST_FREECTX,           (DFUNC)name##_freectx             }, \
    { OSSL_FUNC_DIGEST_DUPCTX,            (DFUNC)name##_dupctx              }, \
    { OSSL_FUNC_DIGEST_GET_PARAMS,        (DFUNC)name##_get_params          }, \
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,   (DFUNC)wp_digest_gettable_params  }, \
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,    (DFUNC)wp_##alg##_set_ctx_params  }, \
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,                                    \
                                          (DFUNC)wp_xof_settable_ctx_params }, \
    { 0,                                  NULL                              }  \
};

/*******************************************************************************
 * SHAKE
 ******************************************************************************/

#ifdef WP_HAVE_SHAKE_256

/**
 * Get the table of supported settable parameters for XOF.
 *
 * @param [in] ctx      Context object. Unused.
 * @param [in] provCtx  Provider context. Unused.
 * @return Table of supported parameters.
 */
static const OSSL_PARAM* wp_xof_settable_ctx_params(void* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_xof_supported_settable_ctx_params[] = {
        {OSSL_DIGEST_PARAM_XOFLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_xof_supported_settable_ctx_params;
}

/** All SHAKE algorithms are eXtendable Output Functions. */
#define WP_SHAKE_FLAGS  WP_DIGEST_FLAG_XOF

/**
 * SHAKE context object.
 * Need to keep the outpt length for finalization.
 */
typedef struct wp_ShakeCtx {
    /** wolfSSL SHAKE object - must be first field. */
    wc_Shake obj;
    /** Output length when finalization is called. */
    size_t outLen;
} wp_ShakeCtx;


IMPLEMENT_DIGEST_NEWCTX(wp_shake, wp_ShakeCtx)
IMPLEMENT_XOF_SET_CTX_PARAMS(wp_shake, wp_ShakeCtx)

IMPLEMENT_XOF(shake, wp_shake_256, wc_Shake, wp_ShakeCtx,
              WC_SHA3_256_BLOCK_SIZE, WC_SHA3_256_DIGEST_SIZE,
              WP_SHAKE_FLAGS,
              wc_InitShake256, wc_Shake256_Update, wc_Shake256_Final,
              wc_Shake256_Copy, wc_Shake256_Free)

#endif


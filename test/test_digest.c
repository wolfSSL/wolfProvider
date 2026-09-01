/* test_digest.c
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

#include "unit.h"

#ifdef WP_HAVE_DIGEST

int test_digest_op(const EVP_MD *md, unsigned char *msg, size_t len,
    unsigned char *prev, unsigned int *prevLen)
{
    int err;
    EVP_MD_CTX *ctx;
    unsigned char digest[64] = {0,};
    unsigned int dLen = sizeof(digest);

    err = (ctx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DigestInit(ctx, md) != 1;
    }
    if (err == 0) {
        err = EVP_DigestUpdate(ctx, msg, len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestUpdate(ctx, msg + len/2, len - len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestFinal_ex(ctx, digest, &dLen) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Digest", digest, dLen);

        if (*prevLen == 0) {
            memcpy(prev, digest, dLen);
            *prevLen = dLen;
        }
        else {
            if (memcmp(digest, prev, *prevLen) != 0) {
                PRINT_ERR_MSG("Digests don't match");
                err = 1;
            }
            else {
                PRINT_MSG("Digests match");
            }
        }
    }

    EVP_MD_CTX_free(ctx);

    return err;
}

/******************************************************************************/
static int test_create_digest(const char *name, void *data)
{
    int err = 0;
    unsigned char *msg = (unsigned char *)"Test pattern";
    unsigned char longMsg[1300];
    unsigned char digest[64];
    unsigned int dLen;
    EVP_MD *omd;
    EVP_MD *wmd;

    (void)data;

    RAND_bytes(longMsg, sizeof(longMsg));

    omd = EVP_MD_fetch(osslLibCtx, name, "");
    wmd = EVP_MD_fetch(wpLibCtx, name, "");

    dLen = 0;
    PRINT_MSG("Digest with OpenSSL");
    err = test_digest_op(omd, msg, strlen((char*)msg), digest, &dLen);
    if (err == 0) {
        PRINT_MSG("Digest With wolfprovider");
        err = test_digest_op(wmd, msg, strlen((char*)msg), digest, &dLen);
    }
    if (err == 0) {
        dLen = 0;
        PRINT_MSG("Digest with OpenSSL");
        err = test_digest_op(omd, longMsg, sizeof(longMsg), digest, &dLen);
    }
    if (err == 0) {
        PRINT_MSG("Digest With wolfprovider");
        err = test_digest_op(wmd, longMsg, sizeof(longMsg), digest, &dLen);
    }

    EVP_MD_free(wmd);
    EVP_MD_free(omd);

    return err;
}

#ifdef WP_HAVE_SHA1

int test_sha(void *data)
{
    return test_create_digest("SHA1", data);
}
#endif /* WP_HAVE_SHA1 */

#ifdef WP_HAVE_SHA224
int test_sha224(void *data)
{
    return test_create_digest("SHA-224", data);
}
#endif

#ifdef WP_HAVE_SHA256
int test_sha256(void *data)
{
    return test_create_digest("SHA256", data);
}
#endif

/******************************************************************************/

#ifdef WP_HAVE_SHA384
int test_sha384(void *data)
{
    return test_create_digest("SHA384", data);
}
#endif

/******************************************************************************/

#ifdef WP_HAVE_SHA512
int test_sha512(void *data)
{
    return test_create_digest("SHA-512", data);
}
#endif

/******************************************************************************/

#ifdef WP_HAVE_SHA512_224
int test_sha512_224(void *data)
{
    return test_create_digest("SHA512-224", data);
}
#endif

/******************************************************************************/

#ifdef WP_HAVE_SHA512_256
int test_sha512_256(void *data)
{
    return test_create_digest("SHA512-256", data);
}
#endif

/******************************************************************************/

#ifdef WP_HAVE_SHA3_224
int test_sha3_224(void *data)
{
    return test_create_digest("SHA3-224", data);
}
#endif

/******************************************************************************/

#ifdef WP_HAVE_SHA3_256
int test_sha3_256(void *data)
{
    return test_create_digest("SHA3-256", data);
}
#endif

/******************************************************************************/

#ifdef WP_HAVE_SHA3_384
int test_sha3_384(void *data)
{
    return test_create_digest("SHA3-384", data);
}
#endif

/******************************************************************************/

#ifdef WP_HAVE_SHA3_512
int test_sha3_512(void *data)
{
    return test_create_digest("SHA3-512", data);
}
#endif

/******************************************************************************/

#ifdef WP_HAVE_SHAKE_256
static int test_xof_op(const EVP_MD *md, unsigned char *msg, size_t len,
    unsigned char *prev, unsigned int *prevLen)
{
    int err;
    EVP_MD_CTX *ctx;
    unsigned char digest[64] = {0,};
    unsigned int dLen = sizeof(digest);

    err = (ctx = EVP_MD_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DigestInit(ctx, md) != 1;
    }
    if (err == 0) {
        err = EVP_DigestInit(ctx, md) != 1;
    }
    if (err == 0) {
        err = EVP_DigestUpdate(ctx, msg, len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestUpdate(ctx, msg + len/2, len - len/2) != 1;
    }
    if (err == 0) {
        err = EVP_DigestFinalXOF(ctx, digest, dLen) != 1;
    }
    if (err == 0) {
        PRINT_BUFFER("Digest", digest, dLen);

        if (*prevLen == 0) {
            memcpy(prev, digest, dLen);
            *prevLen = dLen;
        }
        else {
            if (memcmp(digest, prev, *prevLen) != 0) {
                PRINT_ERR_MSG("Digests don't match");
                err = 1;
            }
            else {
                PRINT_MSG("Digests match");
            }
        }
    }

    EVP_MD_CTX_free(ctx);

    return err;
}

static int test_create_xof(const char *name, void *data)
{
    int err = 0;
    unsigned char *msg = (unsigned char *)"Test pattern";
    unsigned char longMsg[1300];
    unsigned char digest[64];
    unsigned int dLen;
    EVP_MD *omd;
    EVP_MD *wmd;

    (void)data;

    RAND_bytes(longMsg, sizeof(longMsg));

    omd = EVP_MD_fetch(osslLibCtx, name, "");
    wmd = EVP_MD_fetch(wpLibCtx, name, "");

    dLen = 0;
    PRINT_MSG("Digest with OpenSSL");
    err = test_xof_op(omd, msg, strlen((char*)msg), digest, &dLen);
    if (err == 0) {
        PRINT_MSG("Digest With wolfprovider");
        err = test_xof_op(wmd, msg, strlen((char*)msg), digest, &dLen);
    }
    if (err == 0) {
        dLen = 0;
        PRINT_MSG("Digest with OpenSSL");
        err = test_xof_op(omd, longMsg, sizeof(longMsg), digest, &dLen);
    }
    if (err == 0) {
        PRINT_MSG("Digest With wolfprovider");
        err = test_xof_op(wmd, longMsg, sizeof(longMsg), digest, &dLen);
    }

    EVP_MD_free(wmd);
    EVP_MD_free(omd);

    return err;
}
#endif

#ifdef WP_HAVE_SHAKE_256
int test_shake_256(void *data)
{
    return test_create_xof("SHAKE-256", data);
}
#endif

/******************************************************************************/

static int test_digest_dupctx_helper(const char *name, int xof)
{
    static const unsigned char part1[] = "digest-dupctx-part1";
    static const unsigned char part2[] = "digest-dupctx-part2";
    EVP_MD *md = NULL;
    EVP_MD *refMd = NULL;
    EVP_MD_CTX *a = NULL;
    EVP_MD_CTX *b = NULL;
    EVP_MD_CTX *ref = NULL;
    unsigned char outA[64];
    unsigned char outB[64];
    unsigned char outRef[64];
    unsigned int outALen = sizeof(outA);
    unsigned int outBLen = sizeof(outB);
    unsigned int outRefLen = sizeof(outRef);
    int err;

    md = EVP_MD_fetch(wpLibCtx, name, "");
    refMd = EVP_MD_fetch(osslLibCtx, name, "");
    err = (md == NULL) || (refMd == NULL);
    if (err == 0) {
        a = EVP_MD_CTX_new();
        b = EVP_MD_CTX_new();
        ref = EVP_MD_CTX_new();
        err = (a == NULL) || (b == NULL) || (ref == NULL);
    }
    if (err == 0) {
        err = (EVP_DigestInit_ex(a, md, NULL) != 1) ||
            (EVP_DigestInit_ex(ref, refMd, NULL) != 1);
    }
    if (err == 0) {
        err = (EVP_DigestUpdate(a, part1, sizeof(part1)) != 1) ||
            (EVP_DigestUpdate(ref, part1, sizeof(part1)) != 1);
    }
    if (err == 0) {
        err = EVP_MD_CTX_copy_ex(b, a) != 1;
    }
    if (err == 0) {
        err = (EVP_DigestUpdate(a, part2, sizeof(part2)) != 1) ||
            (EVP_DigestUpdate(b, part2, sizeof(part2)) != 1) ||
            (EVP_DigestUpdate(ref, part2, sizeof(part2)) != 1);
    }
    if ((err == 0) && xof) {
        err = (EVP_DigestFinalXOF(a, outA, sizeof(outA)) != 1) ||
            (EVP_DigestFinalXOF(b, outB, sizeof(outB)) != 1) ||
            (EVP_DigestFinalXOF(ref, outRef, sizeof(outRef)) != 1);
    }
    if ((err == 0) && !xof) {
        err = (EVP_DigestFinal_ex(a, outA, &outALen) != 1) ||
            (EVP_DigestFinal_ex(b, outB, &outBLen) != 1) ||
            (EVP_DigestFinal_ex(ref, outRef, &outRefLen) != 1);
    }
    if ((err == 0) && ((outALen != outBLen) || (outALen != outRefLen) ||
            (memcmp(outA, outRef, outALen) != 0) ||
            (memcmp(outB, outRef, outBLen) != 0))) {
        PRINT_ERR_MSG("Digest dupctx mismatch: %s", name);
        err = 1;
    }

    EVP_MD_CTX_free(ref);
    EVP_MD_CTX_free(b);
    EVP_MD_CTX_free(a);
    EVP_MD_free(refMd);
    EVP_MD_free(md);
    return err;
}

int test_digest_dupctx(void *data)
{
    static const struct {
        const char *name;
        int xof;
    } digests[] = {
#if defined(WP_HAVE_MD5) && \
    (!defined(HAVE_FIPS) || defined(WP_ALLOW_NON_FIPS))
        { "MD5", 0 },
#endif
#if defined(WP_HAVE_MD5_SHA1) && \
    (!defined(HAVE_FIPS) || defined(WP_ALLOW_NON_FIPS))
        { "MD5-SHA1", 0 },
#endif
#ifdef WP_HAVE_SHA1
        { "SHA1", 0 },
#endif
#ifdef WP_HAVE_SHA224
        { "SHA-224", 0 },
#endif
#ifdef WP_HAVE_SHA256
        { "SHA256", 0 },
#endif
#ifdef WP_HAVE_SHA384
        { "SHA384", 0 },
#endif
#ifdef WP_HAVE_SHA512
        { "SHA-512", 0 },
#endif
#if defined(WP_HAVE_SHA512) && defined(WP_HAVE_SHA512_224) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
        { "SHA512-224", 0 },
#endif
#if defined(WP_HAVE_SHA512) && defined(WP_HAVE_SHA512_256) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
        { "SHA512-256", 0 },
#endif
#ifdef WP_HAVE_SHA3_224
        { "SHA3-224", 0 },
#endif
#ifdef WP_HAVE_SHA3_256
        { "SHA3-256", 0 },
#endif
#ifdef WP_HAVE_SHA3_384
        { "SHA3-384", 0 },
#endif
#ifdef WP_HAVE_SHA3_512
        { "SHA3-512", 0 },
#endif
#ifdef WP_HAVE_SHAKE_256
        { "SHAKE-256", 1 },
#endif
        { NULL, 0 }
    };
    int err = 0;
    size_t i;

    (void)data;

    for (i = 0; (err == 0) && (digests[i].name != NULL); i++) {
        PRINT_MSG("Digest dupctx: %s", digests[i].name);
        err = test_digest_dupctx_helper(digests[i].name, digests[i].xof);
    }

    return err;
}

/******************************************************************************/

/**
 * Test that digest produces consistent results when data is fed in many small
 * updates vs. a single large update. Exercises the chunked update path
 * (F-1635).
 */
static int test_digest_multi_update_helper(OSSL_LIB_CTX *libCtx)
{
    int err;
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned char data[8192];
    unsigned char digestOne[64];
    unsigned char digestMulti[64];
    unsigned int dLenOne = sizeof(digestOne);
    unsigned int dLenMulti = sizeof(digestMulti);
    size_t i;

    RAND_bytes(data, sizeof(data));

    err = (md = EVP_MD_fetch(libCtx, "SHA-256", "")) == NULL;

    /* Single update */
    if (err == 0) {
        err = (ctx = EVP_MD_CTX_new()) == NULL;
    }
    if (err == 0) {
        err = EVP_DigestInit(ctx, md) != 1;
    }
    if (err == 0) {
        err = EVP_DigestUpdate(ctx, data, sizeof(data)) != 1;
    }
    if (err == 0) {
        err = EVP_DigestFinal_ex(ctx, digestOne, &dLenOne) != 1;
    }
    EVP_MD_CTX_free(ctx);
    ctx = NULL;

    /* Many small updates (64 bytes each) */
    if (err == 0) {
        err = (ctx = EVP_MD_CTX_new()) == NULL;
    }
    if (err == 0) {
        err = EVP_DigestInit(ctx, md) != 1;
    }
    for (i = 0; err == 0 && i < sizeof(data); i += 64) {
        err = EVP_DigestUpdate(ctx, data + i, 64) != 1;
    }
    if (err == 0) {
        err = EVP_DigestFinal_ex(ctx, digestMulti, &dLenMulti) != 1;
    }
    if (err == 0) {
        if (dLenOne != dLenMulti ||
            memcmp(digestOne, digestMulti, dLenOne) != 0) {
            PRINT_ERR_MSG("Multi-update digest doesn't match single update");
            err = 1;
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return err;
}

int test_digest_multi_update(void *data)
{
    int err;

    (void)data;

    PRINT_MSG("Digest multi-update with OpenSSL");
    err = test_digest_multi_update_helper(osslLibCtx);
    if (err == 0) {
        PRINT_MSG("Digest multi-update with wolfProvider");
        err = test_digest_multi_update_helper(wpLibCtx);
    }
    return err;
}

/******************************************************************************/

#endif /* WP_HAVE_DIGEST */

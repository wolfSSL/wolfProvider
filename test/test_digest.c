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

#if defined(WP_HAVE_SHAKE_128) || defined(WP_HAVE_SHAKE_256)
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

#if (OPENSSL_VERSION_NUMBER >= 0x30300000L) && \
    (LIBWOLFSSL_VERSION_HEX >= 0x05005001)
/* Squeeze in chunks across block boundaries, reinitializing and copying the
 * context on the way. No final after squeeze and no squeeze after final. */
static int test_xof_squeeze(EVP_MD *md, int wp, const unsigned char *in,
    size_t inLen, unsigned char *out, size_t *len)
{
    static const size_t chunks[] = { 0, 1, 135, 32, 168, 104, 400, 3 };
    unsigned char tmp[200];
    EVP_MD_CTX *ctx;
    EVP_MD_CTX *dup = NULL;
    size_t i;
    int r;
    int err;

    err = (ctx = EVP_MD_CTX_new()) == NULL;
    for (r = 0; (err == 0) && (r < 2); r++) {
        *len = 0;
        err = (EVP_DigestInit_ex(ctx, md, NULL) != 1) ||
            (EVP_DigestUpdate(ctx, in, inLen / 2) != 1) ||
            (EVP_DigestUpdate(ctx, in + inLen / 2, inLen - inLen / 2) != 1);
        for (i = 0; (err == 0) && (i < sizeof(chunks) / sizeof(*chunks));
                i++) {
            err = EVP_DigestSqueeze(ctx, out + *len, chunks[i]) != 1;
            *len += chunks[i];
        }
    }
    /* wolfProvider refuses absorbing once output started. */
    if ((err == 0) && wp && (EVP_DigestUpdate(ctx, out, 1) == 1)) {
        err = 1;
    }
    if (err == 0) {
        err = ((dup = EVP_MD_CTX_dup(ctx)) == NULL) ||
            (EVP_DigestSqueeze(ctx, out + *len, sizeof(tmp)) != 1) ||
            (EVP_DigestSqueeze(dup, tmp, sizeof(tmp)) != 1) ||
            (memcmp(out + *len, tmp, sizeof(tmp)) != 0);
        *len += sizeof(tmp);
    }
    if ((err == 0) && (EVP_DigestFinalXOF(ctx, tmp, 1) == 1)) {
        err = 1;
    }
    if ((err == 0) && ((EVP_DigestInit_ex(dup, md, NULL) != 1) ||
            (EVP_DigestFinalXOF(dup, tmp, 1) != 1) ||
            (EVP_DigestSqueeze(dup, tmp, 1) == 1))) {
        err = 1;
    }

    EVP_MD_CTX_free(dup);
    EVP_MD_CTX_free(ctx);
    return err;
}
#endif

/* Sizes, default length final and squeeze must match OpenSSL. */
static int test_xof_parity(EVP_MD *omd, EVP_MD *wmd)
{
    static const unsigned char msg[] = "Test pattern";
    unsigned char out[2][1100];
    unsigned int len[2];
    int rc[2];
    EVP_MD *md[2];
    EVP_MD_CTX *ctx = NULL;
    size_t i;
    int err;

    md[0] = omd;
    md[1] = wmd;
    /* Parameters absent (RFC 8702), as OpenSSL 3.0.17+. */
    err = (EVP_MD_get_block_size(omd) != EVP_MD_get_block_size(wmd)) ||
        (EVP_MD_get_size(omd) != EVP_MD_get_size(wmd)) ||
        ((EVP_MD_get_flags(omd) & EVP_MD_FLAG_XOF) == 0) ||
        ((EVP_MD_get_flags(wmd) & EVP_MD_FLAG_XOF) == 0) ||
        ((EVP_MD_get_flags(wmd) & EVP_MD_FLAG_DIGALGID_ABSENT) == 0);
    if (err) {
        PRINT_ERR_MSG("XOF sizes or flags don't match");
    }
    if (err == 0) {
        err = (ctx = EVP_MD_CTX_new()) == NULL;
    }
    for (i = 0; (err == 0) && (i < 2); i++) {
        len[i] = 0;
        rc[i] = EVP_DigestInit_ex(ctx, md[i], NULL) &&
            EVP_DigestUpdate(ctx, msg, sizeof(msg)) &&
            EVP_DigestFinal_ex(ctx, out[i], &len[i]);
    }
    if ((err == 0) && ((rc[0] != rc[1]) || (len[0] != len[1]) ||
            (memcmp(out[0], out[1], len[0]) != 0))) {
        PRINT_ERR_MSG("Default length XOF output doesn't match");
        err = 1;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30400000L
    if (err == 0) {
        size_t xofLen = 64;
        size_t getLen;
        OSSL_PARAM params[2];
        OSSL_PARAM getParams[2];

        /* Size is an alias of XOF length; read back as XOF length. */
        params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE,
            &xofLen);
        params[1] = OSSL_PARAM_construct_end();
        getParams[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN,
            &getLen);
        getParams[1] = OSSL_PARAM_construct_end();
        for (i = 0; (err == 0) && (i < 2); i++) {
            len[i] = 0;
            getLen = 0;
            err = (EVP_DigestInit_ex2(ctx, md[i], params) != 1) ||
                (EVP_MD_CTX_get_params(ctx, getParams) != 1) ||
                (getLen != xofLen) ||
                (EVP_DigestUpdate(ctx, msg, sizeof(msg)) != 1) ||
                (EVP_DigestFinal_ex(ctx, out[i], &len[i]) != 1) ||
                (len[i] != xofLen);
        }
        if (err || (memcmp(out[0], out[1], xofLen) != 0)) {
            PRINT_ERR_MSG("XOF length with final doesn't match");
            err = 1;
        }
    }
#endif
    /* No absorbing or output after final until init (EVP or provider). */
    for (i = 0; (err == 0) && (i < 2); i++) {
        err = (EVP_DigestInit_ex(ctx, wmd, NULL) != 1) ||
            (EVP_DigestUpdate(ctx, msg, sizeof(msg)) != 1) ||
            (EVP_DigestFinalXOF(ctx, out[i], 32) != 1) ||
            (EVP_DigestUpdate(ctx, msg, sizeof(msg)) == 1) ||
            (EVP_DigestFinalXOF(ctx, out[i], 32) == 1);
    }
    if ((err == 0) && (memcmp(out[0], out[1], 32) != 0)) {
        err = 1;
    }
#if (OPENSSL_VERSION_NUMBER >= 0x30300000L) && \
    (LIBWOLFSSL_VERSION_HEX >= 0x05005001)
    {
        static const size_t inLens[] = { 0, 135, 136, 137, 168, 169, 400 };
        unsigned char in[400];
        size_t j;
        size_t sLen[2] = { 0, 0 };

        for (i = 0; i < sizeof(in); i++) {
            in[i] = (unsigned char)i;
        }
        for (j = 0; (err == 0) && (j < sizeof(inLens) / sizeof(*inLens));
                j++) {
            for (i = 0; (err == 0) && (i < 2); i++) {
                err = test_xof_squeeze(md[i], i == 1, in, inLens[j], out[i],
                    &sLen[i]);
            }
            if ((err == 0) && (memcmp(out[0], out[1], sLen[0]) != 0)) {
                PRINT_ERR_MSG("Squeezed XOF output doesn't match");
                err = 1;
            }
        }
    }
#endif
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
    if (err == 0) {
        err = test_xof_parity(omd, wmd);
    }

    EVP_MD_free(wmd);
    EVP_MD_free(omd);

    return err;
}
#endif

#ifdef WP_HAVE_SHAKE_128
int test_shake_128(void *data)
{
    return test_create_xof("SHAKE128", data);
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
#ifdef WP_HAVE_SHAKE_128
        { "SHAKE-128", 1 },
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

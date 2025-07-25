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

#endif /* WP_HAVE_DIGEST */

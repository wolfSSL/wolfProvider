/* wp_dec_epki2pki.c
 *
 * Copyright (C) 2021 wolfSSL Inc.
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
 * along with wolfProvider.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <wolfprovider/alg_funcs.h>

#include <wolfssl/wolfcrypt/asn_public.h>

/* Dummy type for EPKI to PKI context. */
typedef void wp_Epki2Pki;

/* A fake static global context. */
static unsigned char fakeCtx[1];

/**
 * Create a new EPKI to PKI context.
 *
 * No context data required so returning a global context.
 *
 * @param [in] provCtx  Provider context. UUnused.
 * @return  Pointer to context.
 */
static wp_Epki2Pki* wp_epki2pki_newctx(WOLFPROV_CTX* provCtx)
{
    (void)provCtx;
    return fakeCtx;
}

/**
 * Dispose of EPKI to PKI context.
 *
 * Nothing to do as it is a global context.
 *
 * @param [in] ctx  EPKI to PKI context. Unused.
 */
static void wp_epki2pki_freectx(wp_Epki2Pki* ctx)
{
    (void)ctx;
}

/**
 * Decode the EPKI to PKI.
 *
 * @param [in]      ctx        EPKI to PKI context. Unused.
 * @param [in, out] coreBio    BIO wrapped for the core.
 * @param [in]      selection  Which parts of to decode. Unused.
 * @param [in]      dataCb     Callback to pass the decoded data to.
 * @param [in]      dataCbArg  Argument to pass to callback.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argment to pass to password callback.
 * @return  1 on success or not data.
 * @return  0 on failure.
 */
static int wp_epki2pki_decode(wp_Epki2Pki* ctx, OSSL_CORE_BIO* coreBio,
    int selection, OSSL_CALLBACK* dataCb, void* dataCbArg,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    int ok = 1;
    int done = 0;
    int rc;
    unsigned char* data = NULL;
    word32 len = 0;
    char password[1024];
    size_t passwordLen;

    (void)ctx;
    (void)selection;

    /* Read the data from the BIO into buffer that is allocated on the fly. */
    if (!wp_read_der_bio(coreBio, &data, &len)) {
        ok = 0;
    }
    /* No data - nothing to do. */
    else if (data == NULL) {
        done = 1;
    }
    if ((!done) && ok && (!pwCb(password, sizeof(password), &passwordLen, NULL,
            pwCbArg))) {
        done = 1;
    }
    if ((!done) && ok) {
        rc = wc_DecryptPKCS8Key(data, len, password, passwordLen);
        if (rc <= 0) {
            ok = 0;
        }
    }
    if ((!done) && ok) {
        OSSL_PARAM params[4];
        int obj = OSSL_OBJECT_PKEY;

        /* Set the data, structure, type of object and end of list marker. */
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
            data, rc);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_STRUCTURE, (char*)"PrivateKeyInfo", 0);
        params[2] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &obj);
        params[3] = OSSL_PARAM_construct_end();

        /* Call the callback to have it process the PKI data. */
        if (!dataCb(params, dataCbArg)) {
            ok = 0;
        }
    }

    /* Dispose of the EPKI data buffer. */
    OPENSSL_free(data);

    return ok;
}

/** Dispatch table for EPKI to PKI decoder. */
const OSSL_DISPATCH wp_epki_to_pki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,  (DFUNC)wp_epki2pki_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (DFUNC)wp_epki2pki_freectx },
    { OSSL_FUNC_DECODER_DECODE,  (DFUNC)wp_epki2pki_decode },
    { 0, NULL }
};



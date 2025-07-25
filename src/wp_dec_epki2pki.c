/* wp_dec_epki2pki.c
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
#include <openssl/core_object.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <wolfprovider/alg_funcs.h>

#include <wolfssl/wolfcrypt/asn_public.h>

/**
 * EPKI to PKI context.
 */
typedef struct wp_Epki2Pki {
    /** Provider context - useful when duplicating. */
    WOLFPROV_CTX* provCtx;
} wp_Epki2Pki;

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
    wp_Epki2Pki* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = (wp_Epki2Pki*)OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }

    return ctx;
}

/**
 * Dispose of EPKI to PKI context.
 *
 * @param [in] ctx  EPKI to PKI context.
 */
static void wp_epki2pki_freectx(wp_Epki2Pki* ctx)
{
    OPENSSL_free(ctx);
}

#if LIBWOLFSSL_VERSION_HEX < 0x05000000
/**
 * Password callback data.
 */
typedef struct wp_PasswordCbData {
    const char* password;
    size_t passwordLen;
} wp_PasswordCbData;

/**
 * wolfSSL PEM password callback.
 *
 * @param [out] passwd   Password from user.
 * @param [in]  sz       Size of password buffer in bytes.
 * @param [in]  rw       Password for reading or writiing. Unused.
 * @param [in]  userdaa  User callback data.
 * @return  -1 on error.
 * @return  Length of password on success.
 */
static int wp_pem_password_cb(char* passwd, int sz, int rw, void* userdata)
{
    int ret;
    wp_PasswordCbData* cbData = (wp_PasswordCbData*)userdata;

    (void)rw;

    if ((size_t)sz < cbData->passwordLen) {
        ret = -1;
    }
    else {
        XMEMCPY(passwd, cbData->password, cbData->passwordLen);
        ret = cbData->passwordLen;
    }

    return ret;
}

static int wp_DecryptPKCS8Key(byte* input, word32 sz, const char* password,
    int passwordSz)
{
    int ret = 0;
    unsigned char* pem = NULL;
    DerBuffer *der = NULL;
    wp_PasswordCbData cbData = { password, passwordSz };
    EncryptedInfo info;
    int algoId;

    pem = OPENSSL_malloc(sz * 2);
    if (pem == NULL) {
        ret = MEMORY_E;
    }
    if (ret == 0) {
        ret = wc_DerToPem(input, sz, pem, sz * 2, PKCS8_ENC_PRIVATEKEY_TYPE);
        if (ret >= 0) {
            sz = ret;
            ret = 0;
        }
    }
    if (ret == 0) {
        info.passwd_cb = wp_pem_password_cb;
        info.passwd_userdata = (void*)&cbData;
        ret = wc_PemToDer(pem, sz, PKCS8_ENC_PRIVATEKEY_TYPE, &der, NULL, &info,
            &algoId);
    }
    if (ret == 0) {
        DerBuffer* pkcs8Der = NULL;
        word32 pkcs8Sz;

        ret = wc_CreatePKCS8Key(NULL, &pkcs8Sz, der->buffer, der->length,
            algoId, NULL, 0);
        if (ret == LENGTH_ONLY_E) {
            ret = 0;
        }
        if (ret == 0) {
            ret = wc_AllocDer(&pkcs8Der, pkcs8Sz, DYNAMIC_TYPE_KEY, NULL);
        }
        if (ret == 0) {
            ret = wc_CreatePKCS8Key(pkcs8Der->buffer, &pkcs8Der->length,
                der->buffer, der->length, algoId, NULL, 0);
            if (ret > 0) {
                ret = 0;
            }
        }
        wc_FreeDer(&der);
        der = pkcs8Der;
    }
    if (ret == 0) {
        XMEMCPY(input, der->buffer, der->length);
        ret = der->length;
    }

    wc_FreeDer(&der);
    OPENSSL_free(pem);
    return ret;
}
#endif

/**
 * Decode the EPKI to PKI.
 *
 * @param [in]      ctx        EPKI to PKI context. Unused.
 * @param [in, out] coreBio    BIO wrapped for the core.
 * @param [in]      selection  Which parts of to decode. Unused.
 * @param [in]      dataCb     Callback to pass the decoded data to.
 * @param [in]      dataCbArg  Argument to pass to callback.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
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
    word32 tradIdx = 0;

    (void)ctx;
    (void)selection;

    /* Read the data from the BIO into buffer that is allocated on the fly. */
    if (!wp_read_der_bio(ctx->provCtx, coreBio, &data, &len)) {
        ok = 0;
    }
    /* No data - nothing to do. */
    else if (data == NULL) {
        done = 1;
    }
    if (wc_GetPkcs8TraditionalOffset(data, &tradIdx, (word32)len) <= 0) {
        /* This is not PKCS8, we are done */
        done = 1;
        ok = 1;
    }
    if ((!done) && ok) {
        /* Try decrypting without password and look for ASN_PARSE_E to indicate
         * that the format is not PKCS#8 encrypted.
         * TODO: should be parsing the structure without decrypting to
         *       determine it is encrypted PKCS#8.
         */
    #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
        rc = wc_DecryptPKCS8Key(data, len, password, 0);
    #else
        rc = wp_DecryptPKCS8Key(data, len, password, 0);
    #endif
        if (rc == ASN_PARSE_E) {
            done = 1;
            ok = 1;
        }
    }
    if ((!done) && ok && (!pwCb(password, sizeof(password), &passwordLen, NULL,
            pwCbArg))) {
        done = 1;
    }
    if ((!done) && ok) {
    #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
        rc = wc_DecryptPKCS8Key(data, len, password, (int)passwordLen);
    #else
        rc = wp_DecryptPKCS8Key(data, len, password, (int)passwordLen);
    #endif
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

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** Dispatch table for EPKI to PKI decoder. */
const OSSL_DISPATCH wp_epki_to_pki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,  (DFUNC)wp_epki2pki_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (DFUNC)wp_epki2pki_freectx },
    { OSSL_FUNC_DECODER_DECODE,  (DFUNC)wp_epki2pki_decode },
    { 0, NULL }
};



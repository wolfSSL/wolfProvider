/* wp_dec_pem2der.c
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
 * PEM to DER context.
 */
typedef struct wp_Pem2Der {
    /** Provider context - useful when duplicating. */
    WOLFPROV_CTX* provCtx;
} wp_Pem2Der;

/**
 * Create a new PEM to DER context.
 *
 * @param [in] provCtx  Provider context.
 * @return  Pointer to context.
 */
static wp_Pem2Der* wp_pem2der_newctx(WOLFPROV_CTX* provCtx)
{
    wp_Pem2Der* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = (wp_Pem2Der*)OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }

    return ctx;
}

/**
 * Dispose of PEM to DER context.
 *
 * @param [in] ctx  PEM to DER context.
 */
static void wp_pem2der_freectx(wp_Pem2Der* ctx)
{
    OPENSSL_free(ctx);
}

/**
 * Find the start of the PEM header.
 *
 * @param [in] data  Data buffer with PEM encoding.
 * @param [in] len   Length of data in bytes.
 * @return  Index of PEM header on success.
 * @return  Length of data on failure.
 */
static word32 wp_pem2der_find_header(unsigned char* data, word32 len)
{
    word32 i;
    word32 idx = len;

    for (i = 0; i + 10 < len; i++) {
        if ((data[i] == '-') && (XMEMCMP(data + i, "-----BEGIN", 10) == 0)) {
            idx = i;
            break;
        }
    }

    return idx;
}

#ifdef WOLFSSL_ENCRYPTED_KEYS
/**
 * Password callback data.
 */
typedef struct wp_PasswordCbData {
    /** OpenSSL password callback. */
    OSSL_PASSPHRASE_CALLBACK* cb;
    /** Argument to pass to OpenSSL password callback. */
    void* cbArg;
} wp_PasswordCbData;

/**
 * wolfSSL PEM password callback wrapper around OpenSSL callback.
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
    wp_PasswordCbData* osslCb = (wp_PasswordCbData*)userdata;
    size_t len;

    (void)rw;

    if (!osslCb->cb(passwd, sz, &len, NULL, osslCb->cbArg)) {
        ret = -1;
    }
    else {
        ret = (int)len;
    }

    return ret;
}
#endif /* WOLFSSL_ENCRYPTED_KEYS */

/**
 * Convert PEM to DER for unsupported header/footer.
 *
 * wolfSSL does not support PEM encoded EC parameters.
 *
 * @param [in]      data     PEM encoded data.
 * @param [in]      len      Length of data in bytes.
 * @param [out]     pDer     DER Buffer holding decoded data.
 * @param [in, out] info     Information about decodeding PEM.
 * @param [in]      nameLen  Length of name in header and footer.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_pem2der_convert(const char* data, word32 len, DerBuffer** pDer,
    EncryptedInfo* info, int nameLen)
{
    int ok = 1;
    int rc;
    const char* footer;
    const char* base64Data;
    size_t base64Len;

    /* Skip '-----BEGIN <name>-----\n'. */
    base64Data = data + 16 + nameLen + 1;
    base64Len = len - 16 + nameLen + 1;
    footer = XSTRSTR(base64Data, "-----END ");
    if (footer == NULL) {
        info->consumed = len;
        ok = 0;
    }
    if (ok) {
        /* Include footer and '\n'. */
        info->consumed = (long)(footer - data) + 14 + nameLen + 1;
        base64Len = footer - base64Data;
        rc = wc_AllocDer(pDer, (word32)base64Len, ECC_TYPE, NULL);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        rc = Base64_Decode((byte*)base64Data, (word32)base64Len,
            (*pDer)->buffer, &(*pDer)->length);
        if (rc < 0) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decode the PEM data to DER.
 *
 * Looks for a BEGIN line and decodes to the corresponding END.
 *
 * @param [in]  data       PEM data.
 * @param [in]  len        Length of PEM data in bytes.
 * @param [in]  dataCb     Callback to pass the decoded data to.
 * @param [in]  dataCbArg  Argument to pass to callback.
 * @param [in]  pwCb       Password callback.
 * @param [in]  pwCbArg    Argument to pass to password callback.
 * @return  1 on success or not data.
 * @return  0 on failure.
 */
static int wp_pem2der_decode_data(const unsigned char* data, word32 len,
    OSSL_CALLBACK* dataCb, void* dataCbArg, OSSL_PASSPHRASE_CALLBACK* pwCb,
    void* pwCbArg)
{
    int ok = 1;
    int done = 0;
    int rc;
    int algoId;
    int type;
    const char* dataType = NULL;
    const char* dataFormat = NULL;
    int obj;
    EncryptedInfo info;
    DerBuffer* der = NULL;
    OSSL_PARAM params[5];
    OSSL_PARAM* p = params;
#ifdef WOLFSSL_ENCRYPTED_KEYS
    wp_PasswordCbData wpPwCb = { pwCb, pwCbArg };
#endif

    (void)pwCb;
    (void)pwCbArg;

    XMEMSET(&info, 0, sizeof(info));

    /* Identify the type of object by looking at the header. */
    /* TODO: support more PEM headers. */
    if (XMEMCMP(data, "-----BEGIN CERTIFICATE-----", 27) == 0) {
        type = CERT_TYPE;
        obj = OSSL_OBJECT_CERT;
    }
#if LIBWOLFSSL_VERSION_HEX > 0x05007006
    else if (XMEMCMP(data, "-----BEGIN TRUSTED CERTIFICATE-----", 35) == 0) {
        type = TRUSTED_CERT_TYPE;
        obj = OSSL_OBJECT_CERT;
    }
#else
    else if (XMEMCMP(data, "-----BEGIN TRUSTED CERTIFICATE-----", 35) == 0) {
        type = CERT_TYPE;
        obj = OSSL_OBJECT_CERT;
        if (!wp_pem2der_convert((const char*)data, len, &der, &info,
                XSTRLEN("TRUSTED CERTIFICATE"))) {
            ok = 0;
        }
        done = 1;
    }
#endif
    else if (XMEMCMP(data, "-----BEGIN X509 CRL-----", 24) == 0) {
        type = CRL_TYPE;
        obj = OSSL_OBJECT_CRL;
    }
    else if (XMEMCMP(data, "-----BEGIN RSA PRIVATE KEY-----", 31) == 0) {
        type = RSA_TYPE;
        dataType = "RSA";
        dataFormat = "type-specific";
        obj = OSSL_OBJECT_PKEY;
    #ifdef WOLFSSL_ENCRYPTED_KEYS
        if (XMEMCMP(data + 32, "Proc-Type", 9) == 0) {
            info.passwd_cb = wp_pem_password_cb;
            info.passwd_userdata = (void*)&wpPwCb;
        }
    #endif
    }
    else if (XMEMCMP(data, "-----BEGIN EC PARAMETERS-----", 29) == 0) {
        dataType = "EC";
        dataFormat = "type-specific";
        obj = OSSL_OBJECT_PKEY;
        if (!wp_pem2der_convert((const char*)data, len, &der, &info,
                XSTRLEN("EC PARAMETERS"))) {
            ok = 0;
        }
        done = 1;
    }
    else if (XMEMCMP(data, "-----BEGIN EC PRIVATE KEY-----", 30) == 0) {
        type = ECC_TYPE;
        dataType = "EC";
        dataFormat = "type-specific";
        obj = OSSL_OBJECT_PKEY;
    #ifdef WOLFSSL_ENCRYPTED_KEYS
        if (XMEMCMP(data + 31, "Proc-Type", 9) == 0) {
            info.passwd_cb = wp_pem_password_cb;
            info.passwd_userdata = (void*)&wpPwCb;
        }
    #endif
    }
    else if (XMEMCMP(data, "-----BEGIN PRIVATE KEY-----", 27) == 0) {
        type = PKCS8_PRIVATEKEY_TYPE;
        dataType = NULL;
        dataFormat = "PrivateKeyInfo";
        obj = OSSL_OBJECT_PKEY;
    }
    else if (XMEMCMP(data, "-----BEGIN PUBLIC KEY-----", 26) == 0) {
        type = PUBLICKEY_TYPE;
        dataType = NULL;
        dataFormat = "SubjectPublicKeyInfo";
        obj = OSSL_OBJECT_PKEY;
    }
    else if ((XMEMCMP(data, "-----BEGIN DH PARAMETERS-----", 29) == 0) ||
             (XMEMCMP(data, "-----BEGIN X9.42 DH PARAMETERS-----", 35) == 0)) {
        type = DH_PARAM_TYPE;
        dataType = NULL;
        dataFormat = "type-specific";
        obj = OSSL_OBJECT_PKEY;
    }
#ifdef WOLFSSL_ENCRYPTED_KEYS
    else if (XMEMCMP(data, "-----BEGIN ENCRYPTED PRIVATE KEY-----", 37) == 0) {
        type = PKCS8_ENC_PRIVATEKEY_TYPE;
        dataType = NULL;
        dataFormat = "PrivateKeyInfo";
        obj = OSSL_OBJECT_PKEY;

        info.passwd_cb = wp_pem_password_cb;
        info.passwd_userdata = (void*)&wpPwCb;
    }
#endif
    else {
        ok = 0;
    }

    if (ok && !done) {
        /* Decode the PEM to DER using wolfSSL. */
        rc = wc_PemToDer(data, len, type, &der, NULL, &info, &algoId);
        if (rc != 0) {
            ok = 0;
        }
    #if LIBWOLFSSL_VERSION_HEX < 0x05000000
        /* Put back PKCS #8 wrapper so the OID can be checked. */
        if (ok && ((type ==PKCS8_PRIVATEKEY_TYPE) ||
                   (type == PKCS8_ENC_PRIVATEKEY_TYPE))) {
            DerBuffer* pkcs8Der = NULL;
            word32 pkcs8Sz;

            rc = wc_CreatePKCS8Key(NULL, &pkcs8Sz, der->buffer, der->length,
                algoId, NULL, 0);
            if (rc != LENGTH_ONLY_E) {
                ok = 0;
            }
            if (ok) {
                rc = wc_AllocDer(&pkcs8Der, pkcs8Sz, DYNAMIC_TYPE_KEY, NULL);
                if (rc != 0) {
                    ok = 0;
                }
            }
            if (ok) {
                rc = wc_CreatePKCS8Key(pkcs8Der->buffer, &pkcs8Der->length,
                    der->buffer, der->length, algoId, NULL, 0);
                if (rc < 0) {
                    ok = 0;
                }
            }
            wc_FreeDer(&der);
            der = pkcs8Der;
        }
    #endif
    }

    /* Construct parameters to pass to callback. */
    if (ok && (dataType != NULL)) {
        /* For keys, set the key type from the header. */
        *(p++) = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
            (char*)dataType, 0);
    }
    if (ok && (dataFormat != NULL)) {
        /* For keys, set the key format from the header. */
        *(p++) = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_STRUCTURE, (char*)dataFormat, 0);
    }
    if (ok) {
        /* Set the data, type of object and end of list marker. */
        *(p++) = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
            der->buffer, der->length);
        *(p++) = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &obj);
        *(p++) = OSSL_PARAM_construct_end();

        /* Call the callback to have it process the DER data. */
        if (!dataCb(params, dataCbArg)) {
            ok = 0;
        }
    }

    /* Dispose of the DER data buffer now that callback has used it. */
    wc_FreeDer(&der);

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decode the PEM to DER.
 *
 * @param [in]      ctx        PEM to DER context. Unused.
 * @param [in, out] coreBio    BIO wrapped for the core.
 * @param [in]      selection  Which parts of to decode. Unused.
 * @param [in]      dataCb     Callback to pass the decoded data to.
 * @param [in]      dataCbArg  Argument to pass to callback.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
 * @return  1 on success or not data.
 * @return  0 on failure.
 */
static int wp_pem2der_decode(wp_Pem2Der* ctx, OSSL_CORE_BIO* coreBio,
    int selection, OSSL_CALLBACK* dataCb, void* dataCbArg,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    int ok = 1;
    int done = 0;
    unsigned char* data = NULL;
    word32 len = 0;
    word32 idx = 0;

    (void)ctx;
    (void)selection;

    /* Read the data from the BIO into buffer that is allocated on the fly. */
    if (!wp_read_pem_bio(ctx->provCtx, coreBio, &data, &len)) {
        ok = 0;
    }
    /* No data - nothing to do. */
    else if (data == NULL) {
        done = 1;
    }
    if (!done) {
        idx += wp_pem2der_find_header(data + idx, len - idx);
        /* No header means nothing to do. */
        if (idx == len) {
            done = 1;
        }
        if (!done) {
            ok = wp_pem2der_decode_data(data + idx, len - idx, dataCb,
                dataCbArg, pwCb, pwCbArg);
        }
    }
    /* Dispose of the PEM data buffer. */
    OPENSSL_free(data);

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** Dispatch table for PEM to DER decoder. */
const OSSL_DISPATCH wp_pem_to_der_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,  (DFUNC)wp_pem2der_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (DFUNC)wp_pem2der_freectx },
    { OSSL_FUNC_DECODER_DECODE,  (DFUNC)wp_pem2der_decode },
    { 0, NULL }
};



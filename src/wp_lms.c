/* wp_lms.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
 */

#include <limits.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/bio.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>

#ifdef WP_HAVE_LMS

#include <wolfssl/wolfcrypt/wc_lms.h>

#define WP_LMS_LEVELS_SZ 4
#define WP_LMS_TYPE_SZ   4
#define WP_LMS_XDR_MIN_SZ 48
#define WP_LMS_XDR_MAX_SZ 56

typedef struct wp_Lms {
    LmsKey key;
    unsigned char pub[WP_LMS_XDR_MAX_SZ];
    size_t pubLen;
    WOLFPROV_CTX* provCtx;
#ifndef WP_SINGLE_THREADED
    wolfSSL_Mutex mutex;
#endif
    int refCnt;
} wp_Lms;

typedef struct wp_LmsSigCtx {
    WOLFPROV_CTX* provCtx;
    wp_Lms* lms;
} wp_LmsSigCtx;

static size_t wp_lms_xdr_pub_len(const unsigned char* header);
static int wp_lms_selection_ok(int selection);

static wp_Lms* wp_lms_new(WOLFPROV_CTX* provCtx)
{
    wp_Lms* lms = NULL;

    if (wolfssl_prov_is_running()) {
        lms = OPENSSL_zalloc(sizeof(*lms));
    }
    if (lms != NULL) {
        if (wc_LmsKey_Init(&lms->key, NULL, INVALID_DEVID) != 0) {
            OPENSSL_free(lms);
            lms = NULL;
        }
        else {
#ifndef WP_SINGLE_THREADED
            if (wc_InitMutex(&lms->mutex) != 0) {
                wc_LmsKey_Free(&lms->key);
                OPENSSL_free(lms);
                lms = NULL;
            }
#endif
        }
        if (lms != NULL) {
            lms->provCtx = provCtx;
            lms->refCnt = 1;
        }
    }

    return lms;
}

static void wp_lms_free(wp_Lms* lms)
{
    if (lms != NULL) {
        int cnt;
#ifndef WP_SINGLE_THREADED
        if (wc_LockMutex(&lms->mutex) == 0) {
            cnt = --lms->refCnt;
            wc_UnLockMutex(&lms->mutex);
        }
        else {
            /* Cannot safely decrement without the lock; keep the object. */
            cnt = lms->refCnt;
        }
#else
        cnt = --lms->refCnt;
#endif
        if (cnt == 0) {
#ifndef WP_SINGLE_THREADED
            wc_FreeMutex(&lms->mutex);
#endif
            wc_LmsKey_Free(&lms->key);
            OPENSSL_clear_free(lms, sizeof(*lms));
        }
    }
}

static int wp_lms_up_ref(wp_Lms* lms)
{
    if (lms == NULL) {
        return 0;
    }
#ifndef WP_SINGLE_THREADED
    if (wc_LockMutex(&lms->mutex) != 0) {
        return 0;
    }
#endif
    lms->refCnt++;
#ifndef WP_SINGLE_THREADED
    wc_UnLockMutex(&lms->mutex);
#endif
    return 1;
}

static int wp_lms_has(const wp_Lms* lms, int selection)
{
    int ok = wolfssl_prov_is_running() && (lms != NULL);

    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        ok = lms->pubLen != 0;
    }

    return ok;
}

static int wp_lms_match(const wp_Lms* lms1, const wp_Lms* lms2,
    int selection)
{
    int ok = wolfssl_prov_is_running() && (lms1 != NULL) && (lms2 != NULL);

    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        ok = 0;
    }
    if (ok && ((lms1->pubLen == 0) || (lms2->pubLen == 0))) {
        ok = 0;
    }
    if (ok) {
        ok = XMEMCMP(lms1->pub, lms2->pub, 2 * WP_LMS_TYPE_SZ) == 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        ok = (lms1->pubLen == lms2->pubLen) &&
            (XMEMCMP(lms1->pub, lms2->pub, lms1->pubLen) == 0);
    }

    return ok;
}

static int wp_lms_validate(const wp_Lms* lms, int selection, int checkType)
{
    (void)checkType;

    return wp_lms_has(lms, selection);
}

static int wp_lms_import(wp_Lms* lms, int selection,
    const OSSL_PARAM params[])
{
    int ok = wolfssl_prov_is_running() && (lms != NULL) && (params != NULL);
    int importSelection = selection;
    const OSSL_PARAM* p = NULL;
    const void* pub = NULL;
    size_t pubLen = 0;
    unsigned char raw[WP_LMS_LEVELS_SZ + WP_LMS_XDR_MAX_SZ];

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_lms_import");

    if ((importSelection & OSSL_KEYMGMT_SELECT_KEYPAIR) ==
            OSSL_KEYMGMT_SELECT_KEYPAIR) {
        importSelection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    }
    if (ok && !wp_lms_selection_ok(importSelection)) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if ((p == NULL) ||
                !OSSL_PARAM_get_octet_string_ptr(p, &pub, &pubLen) ||
                (pub == NULL)) {
            p = OSSL_PARAM_locate_const(params,
                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
            ok = (p != NULL) &&
                OSSL_PARAM_get_octet_string_ptr(p, &pub, &pubLen) &&
                (pub != NULL);
        }
    }
    if (ok && ((pubLen < WP_LMS_XDR_MIN_SZ) ||
            (pubLen > WP_LMS_XDR_MAX_SZ))) {
        ok = 0;
    }
    if (ok && (pubLen != wp_lms_xdr_pub_len((const unsigned char*)pub))) {
        ok = 0;
    }
    if (ok) {
        raw[0] = 0;
        raw[1] = 0;
        raw[2] = 0;
        raw[3] = 1;
        XMEMCPY(raw + WP_LMS_LEVELS_SZ, pub, pubLen);
        ok = wc_LmsKey_ImportPubRaw(&lms->key, raw,
            (word32)(pubLen + WP_LMS_LEVELS_SZ)) == 0;
    }
    if (ok) {
        XMEMCPY(lms->pub, pub, pubLen);
        lms->pubLen = pubLen;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PQC,
        __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static const OSSL_PARAM wp_lms_imexport_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM* wp_lms_import_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) ==
            OSSL_KEYMGMT_SELECT_KEYPAIR) {
        return wp_lms_imexport_types;
    }
    if (!wp_lms_selection_ok(selection)) {
        return NULL;
    }
    return wp_lms_imexport_types;
}

static const OSSL_PARAM* wp_lms_export_types(int selection)
{
    return wp_lms_import_types(selection);
}

static const OSSL_PARAM* wp_lms_gettable_params(WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    (void)provCtx;
    return params;
}

static int wp_lms_get_params(wp_Lms* lms, OSSL_PARAM params[])
{
    int ok = (lms != NULL) && (lms->pubLen != 0);
    OSSL_PARAM* p;
    word32 sigLen = 0;
    int bits;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_lms_get_params");

    if (ok) {
        bits = (lms->pubLen == WP_LMS_XDR_MIN_SZ) ? 192 : 256;
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if ((p != NULL) && !OSSL_PARAM_set_int(p, (int)(8 * lms->pubLen))) {
            ok = 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if ((p != NULL) && !OSSL_PARAM_set_int(p, bits)) {
            ok = 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        if ((p != NULL) && !OSSL_PARAM_set_octet_string(p, lms->pub,
                lms->pubLen)) {
            ok = 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        if ((p != NULL) && !OSSL_PARAM_set_octet_string(p, lms->pub,
                lms->pubLen)) {
            ok = 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if (p != NULL) {
            if ((wc_LmsKey_GetSigLen(&lms->key, &sigLen) != 0) ||
                    (sigLen < WP_LMS_LEVELS_SZ) ||
                    !OSSL_PARAM_set_int(p,
                        (int)sigLen - WP_LMS_LEVELS_SZ)) {
                ok = 0;
            }
        }
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC,
        __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static wp_Lms* wp_lms_dup(const wp_Lms* src, int selection)
{
    wp_Lms* dst = NULL;
    OSSL_PARAM params[2];

    if ((src != NULL) &&
            ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        dst = wp_lms_new(src->provCtx);
        if (dst != NULL) {
            params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY, (void*)src->pub, src->pubLen);
            params[1] = OSSL_PARAM_construct_end();
            if (!wp_lms_import(dst, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, params)) {
                wp_lms_free(dst);
                dst = NULL;
            }
        }
    }
    return dst;
}

static int wp_lms_export(wp_Lms* lms, int selection, OSSL_CALLBACK* paramCb,
    void* cbArg)
{
    int ok = wolfssl_prov_is_running() && (lms != NULL) &&
        (paramCb != NULL) &&
        ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) &&
        (lms->pubLen != 0);
    OSSL_PARAM params[2];

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_lms_export");

    if (ok) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
            lms->pub, lms->pubLen);
        params[1] = OSSL_PARAM_construct_end();
        ok = paramCb(params, cbArg);
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PQC,
        __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static wp_Lms* wp_lms_load(const void* reference, size_t referenceSz)
{
    wp_Lms* lms = NULL;

    if (wolfssl_prov_is_running() && (reference != NULL) &&
            (referenceSz == sizeof(lms))) {
        lms = *(wp_Lms**)reference;
        *(wp_Lms**)reference = NULL;
    }

    return lms;
}

static const char* wp_lms_query_operation_name(int operationId)
{
    return operationId == OSSL_OP_SIGNATURE ? "LMS" : NULL;
}

const OSSL_DISPATCH wp_lms_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (DFUNC)wp_lms_new },
    { OSSL_FUNC_KEYMGMT_FREE, (DFUNC)wp_lms_free },
    { OSSL_FUNC_KEYMGMT_DUP, (DFUNC)wp_lms_dup },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (DFUNC)wp_lms_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (DFUNC)wp_lms_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (DFUNC)wp_lms_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (DFUNC)wp_lms_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (DFUNC)wp_lms_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (DFUNC)wp_lms_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (DFUNC)wp_lms_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (DFUNC)wp_lms_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (DFUNC)wp_lms_export_types },
    { OSSL_FUNC_KEYMGMT_LOAD, (DFUNC)wp_lms_load },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        (DFUNC)wp_lms_query_operation_name },
    { 0, NULL }
};

static wp_LmsSigCtx* wp_lms_sig_newctx(WOLFPROV_CTX* provCtx,
    const char* propq)
{
    wp_LmsSigCtx* ctx = NULL;

    (void)propq;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }

    return ctx;
}

static void wp_lms_sig_freectx(wp_LmsSigCtx* ctx)
{
    if (ctx != NULL) {
        wp_lms_free(ctx->lms);
        OPENSSL_free(ctx);
    }
}

static wp_LmsSigCtx* wp_lms_sig_dupctx(const wp_LmsSigCtx* src)
{
    wp_LmsSigCtx* dst = NULL;

    if (src != NULL) {
        dst = OPENSSL_zalloc(sizeof(*dst));
        if (dst != NULL) {
            dst->provCtx = src->provCtx;
            if ((src->lms != NULL) && !wp_lms_up_ref(src->lms)) {
                OPENSSL_free(dst);
                dst = NULL;
            }
            else {
                dst->lms = src->lms;
            }
        }
    }
    return dst;
}

static int wp_lms_verify_message_init(wp_LmsSigCtx* ctx, wp_Lms* lms,
    const OSSL_PARAM params[])
{
    int ok = wolfssl_prov_is_running() && (ctx != NULL);

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_lms_verify_message_init");

    (void)params;

    if (ok && (lms == NULL) && (ctx->lms == NULL)) {
        ok = 0;
    }
    if (ok && (lms != NULL)) {
        if (!wp_lms_up_ref(lms)) {
            ok = 0;
        }
        if (ok) {
            wp_lms_free(ctx->lms);
            ctx->lms = lms;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PQC,
        __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static int wp_lms_verify(wp_LmsSigCtx* ctx, const unsigned char* sig,
    size_t sigLen, const unsigned char* msg, size_t msgLen)
{
    int ok = wolfssl_prov_is_running() && (ctx != NULL) &&
        (ctx->lms != NULL) && (sig != NULL) &&
        ((msg != NULL) || (msgLen == 0));
    unsigned char* rawSig = NULL;
    unsigned char empty = 0;
    word32 expectedRawSigLen = 0;
    size_t rawSigLen = 0;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_lms_verify");

    if (ok && ((wc_LmsKey_GetSigLen(&ctx->lms->key,
            &expectedRawSigLen) != 0) ||
            (expectedRawSigLen < WP_LMS_LEVELS_SZ) ||
            (sigLen != (size_t)expectedRawSigLen - WP_LMS_LEVELS_SZ) ||
            (msgLen > INT_MAX))) {
        ok = 0;
    }
    if (ok) {
        rawSigLen = expectedRawSigLen;
        rawSig = OPENSSL_malloc(rawSigLen);
        ok = rawSig != NULL;
    }
    if (ok) {
        XMEMSET(rawSig, 0, WP_LMS_LEVELS_SZ);
        XMEMCPY(rawSig + WP_LMS_LEVELS_SZ, sig, sigLen);
        if (msg == NULL) {
            msg = &empty;
        }
        ok = wc_LmsKey_Verify(&ctx->lms->key, rawSig,
            (word32)rawSigLen, msg, (int)msgLen) == 0;
    }

    OPENSSL_clear_free(rawSig, rawSigLen);

    WOLFPROV_LEAVE(WP_LOG_COMP_PQC,
        __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

const OSSL_DISPATCH wp_lms_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (DFUNC)wp_lms_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (DFUNC)wp_lms_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (DFUNC)wp_lms_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
        (DFUNC)wp_lms_verify_message_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (DFUNC)wp_lms_verify },
    { 0, NULL }
};

typedef struct wp_LmsDecCtx {
    WOLFPROV_CTX* provCtx;
    int selection;
} wp_LmsDecCtx;

static wp_LmsDecCtx* wp_lms_dec_new(WOLFPROV_CTX* provCtx)
{
    wp_LmsDecCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }
    return ctx;
}

static void wp_lms_dec_free(wp_LmsDecCtx* ctx)
{
    OPENSSL_free(ctx);
}

static int wp_lms_selection_ok(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        return 0;
    }
    return 1;
}

static int wp_lms_dec_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_lms_dec_selection");
    (void)provCtx;
    ok = wp_lms_selection_ok(selection);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC,
        __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static int wp_lms_dec_export(wp_LmsDecCtx* ctx, const void* reference,
    size_t referenceSz, OSSL_CALLBACK* exportCb, void* exportCbArg)
{
    wp_Lms* lms = NULL;
    int selection;

    if ((ctx == NULL) || (reference == NULL) ||
            (referenceSz != sizeof(lms)) || (exportCb == NULL)) {
        return 0;
    }
    lms = *(wp_Lms* const*)reference;
    selection = ctx->selection;
    if (selection == 0) {
        selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    }
    return wp_lms_export(lms, selection, exportCb, exportCbArg);
}

static size_t wp_lms_xdr_pub_len(const unsigned char* header)
{
    word32 lmsType = ((word32)header[0] << 24) |
        ((word32)header[1] << 16) | ((word32)header[2] << 8) | header[3];
    size_t len = 0;

    if (((lmsType >= 5) && (lmsType <= 9)) ||
            ((lmsType >= 15) && (lmsType <= 19))) {
        len = WP_LMS_XDR_MAX_SZ;
    }
    else if (((lmsType >= 10) && (lmsType <= 14)) ||
            ((lmsType >= 20) && (lmsType <= 24))) {
        len = WP_LMS_XDR_MIN_SZ;
    }
    return len;
}

static int wp_lms_bio_read(BIO* bio, unsigned char* data, size_t len)
{
    size_t offset = 0;

    while (offset < len) {
        int readLen = BIO_read(bio, data + offset, (int)(len - offset));

        if (readLen <= 0) {
            return 0;
        }
        offset += (size_t)readLen;
    }
    return 1;
}

static int wp_lms_dec_decode(wp_LmsDecCtx* ctx, OSSL_CORE_BIO* cBio,
    int selection, OSSL_CALLBACK* dataCb, void* dataCbArg,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    BIO* bio = NULL;
    wp_Lms* lms = NULL;
    unsigned char pub[WP_LMS_XDR_MAX_SZ];
    size_t pubLen = 0;
    int ok = 0;
    OSSL_PARAM params[4];
    OSSL_PARAM importParams[2];
    int objectType = OSSL_OBJECT_PKEY;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_lms_dec_decode");

    (void)pwCb;
    (void)pwCbArg;
    if (!wolfssl_prov_is_running() || (ctx == NULL) ||
            (dataCb == NULL) || !wp_lms_selection_ok(selection)) {
        goto done;
    }
    bio = wp_corebio_get_bio(ctx->provCtx, cBio);
    if (bio == NULL) {
        goto done;
    }
    ctx->selection = selection;
    if (!wp_lms_bio_read(bio, pub, WP_LMS_LEVELS_SZ)) {
        ok = 1;
        goto done;
    }
    pubLen = wp_lms_xdr_pub_len(pub);
    if (pubLen == 0) {
        ok = 1;
        goto done;
    }
    if (!wp_lms_bio_read(bio, pub + WP_LMS_LEVELS_SZ,
            pubLen - WP_LMS_LEVELS_SZ)) {
        ok = 1;
        goto done;
    }
    lms = wp_lms_new(ctx->provCtx);
    if (lms == NULL) {
        goto done;
    }
    importParams[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY, pub, pubLen);
    importParams[1] = OSSL_PARAM_construct_end();
    if (!wp_lms_import(lms, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, importParams)) {
        wp_lms_free(lms);
        lms = NULL;
        ok = 1;
        goto done;
    }
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE,
        &objectType);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
        (char*)WP_NAMES_LMS, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
        &lms, sizeof(lms));
    params[3] = OSSL_PARAM_construct_end();
    ok = dataCb(params, dataCbArg);
    wp_lms_free(lms);

done:
    BIO_free(bio);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC,
        __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

const OSSL_DISPATCH wp_lms_xdr_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (DFUNC)wp_lms_dec_new },
    { OSSL_FUNC_DECODER_FREECTX, (DFUNC)wp_lms_dec_free },
    { OSSL_FUNC_DECODER_DOES_SELECTION, (DFUNC)wp_lms_dec_selection },
    { OSSL_FUNC_DECODER_DECODE, (DFUNC)wp_lms_dec_decode },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT, (DFUNC)wp_lms_dec_export },
    { 0, NULL }
};

#endif /* WP_HAVE_LMS */

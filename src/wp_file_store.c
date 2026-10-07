/* wp_file_store.c
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
#include <openssl/store.h>
#include <openssl/decoder.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#include <wolfssl/wolfcrypt/types.h>

/* TODO: support directory access. */

/**
 * File system context.
 */
typedef struct wp_FileCtx {
    /** URI of resource. */
    char* uri;
    /** BIO wrapping access to a file. */
    BIO* bio;

    /** Provider context - used to get library context. */
    WOLFPROV_CTX* provCtx;

    /** Decoder context for processing the contents of the file. */
    OSSL_DECODER_CTX* decCtx;
    /** Properties query. */
    char* propQuery;
    /** Type of data: key, certificate, CRL, ... */
    int type;
    /** Format of file data. */
    char* format;
} wp_FileCtx;


/**
 * Create a new file system context object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New file system context object on success.
 * @return  NULL on failure.
 */
static wp_FileCtx* wp_filectx_new(WOLFPROV_CTX* provCtx)
{
    wp_FileCtx* ctx = NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }

    return ctx;
}

/**
 * Dispose of ECC key object.
 *
 * @param [in, out] ctx  file system context object.
 */
static void wp_filectx_free(wp_FileCtx* ctx)
{
    if (ctx != NULL) {
        OPENSSL_free(ctx->format);
        OPENSSL_free(ctx->propQuery);
        OSSL_DECODER_CTX_free(ctx->decCtx);
        BIO_free(ctx->bio);
        OPENSSL_free(ctx->uri);
        OPENSSL_free(ctx);
    }
}

/**
 * Create a file system context object from a URI.
 *
 * @param [in] provCtx  Provider context.
 * @param [in] uri      Uniform resource identifier.
 * @return  New file system context object on success.
 * @return  NULL on failure.
 */
static wp_FileCtx* wp_file_open(WOLFPROV_CTX* provCtx, const char* uri)
{
    wp_FileCtx* ctx;

    ctx = wp_filectx_new(provCtx);
    if (ctx != NULL) {
        int ok = 1;

        if (OPENSSL_strncasecmp(uri, "file:", 5) == 0) {
            uri += 5;
            if (OPENSSL_strncasecmp(uri, "//", 2) == 0) {
                /* TODO: may need more uri processing for windows cases */
                uri += 2;
            }
        }
        ctx->uri = OPENSSL_strdup(uri);
        if (ctx->uri == NULL) {
            ok = 0;
        }
        if (ok) {
            if (ctx->bio != NULL) {
                BIO_free(ctx->bio);
            }
            /* Create a BIO to access file. */
            ctx->bio = BIO_new_file(uri, "rb");
            if (ctx->bio == NULL) {
                ok = 0;
            }
        }

        if (!ok) {
            wp_filectx_free(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

/**
 * Create a file system context object from a core BIO.
 *
 * @param [in] provCtx  Provider context.
 * @param [in] cBio     Core BIO.
 * @return  New file system context object on success.
 * @return  NULL on failure.
 */
static wp_FileCtx* wp_file_attach(WOLFPROV_CTX* provCtx, OSSL_CORE_BIO* cBio)
{
    wp_FileCtx* ctx;

    ctx = wp_filectx_new(provCtx);
    if (ctx != NULL) {
        if (ctx->bio != NULL) {
            BIO_free(ctx->bio);
        }
        /* Get the internal BIO. */
        ctx->bio = wp_corebio_get_bio(provCtx, cBio);
    }

    return ctx;
}

/**
 * Return an array of supported settable parameters for the file system context.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_file_settable_ctx_params(WOLFPROV_CTX* provCtx)
{
   /**
     * Supported settable parameters for file system context.
     */
    static const OSSL_PARAM wp_supported_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
        OSSL_PARAM_octet_string(OSSL_STORE_PARAM_SUBJECT, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_INPUT_TYPE, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_supported_settable_ctx_params;
}

/**
 * Set the file system context parameters.
 *
 * @param [in, out] ctx     File system context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_file_set_ctx_params(wp_FileCtx* ctx, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM *p;

    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_file_set_ctx_params");

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_PROPERTIES);
    if (p != NULL) {
        OPENSSL_free(ctx->propQuery);
        ctx->propQuery = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &ctx->propQuery, 0)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_INPUT_TYPE);
        if (p != NULL) {
            OPENSSL_free(ctx->format);
            ctx->format = NULL;
            if (!OSSL_PARAM_get_utf8_string(p, &ctx->format, 0)) {
                ok = 0;
            }
        }
    }
    if (ok && !wp_params_get_int(params, OSSL_STORE_PARAM_EXPECT, &ctx->type)) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_SUBJECT);
        if (p != NULL) {
            /* TODO: only when a directory. */
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * File loading data passed to decoder.
 */
typedef struct wp_FileLoadData {
    /** Callback that processes parameters. */
    OSSL_CALLBACK* cb;
    /** Callback argument. */
    void* cbArg;
} wp_FileLoadData;

/**
 * Constructor for decoder.
 *
 * @param [in] decoder  Data decoder. Unused.
 * @param [in] params   Array of parameters and values.
 * @param [in] data     File loading data.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_file_load_construct(OSSL_DECODER_INSTANCE* decoder,
   const OSSL_PARAM* params, wp_FileLoadData* data)
{
    (void)decoder;
    return data->cb(params, data->cbArg);
}

/**
 * Dispose of file loading data.
 */
static void wp_file_load_cleanup(wp_FileLoadData* data)
{
    (void)data;
    /* Nothing to free - just the callbacks data in here. */
}

/**
 * Set the input structure into decoder context.
 *
 * @param [in, out] decCtx  OpenSSL decoder context.
 * @param [in]      type    Type of info stored.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_file_decoder_set_input_structure(OSSL_DECODER_CTX* decCtx,
    int type)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_file_decoder_set_input_structure");

    switch (type) {
        case OSSL_STORE_INFO_CERT:
            if (!OSSL_DECODER_CTX_set_input_structure(decCtx, "Certificate")) {
                ok = 0;
            }
            break;
        case OSSL_STORE_INFO_CRL:
            if (!OSSL_DECODER_CTX_set_input_structure(decCtx,
                    "CertificateList")) {
                ok = 0;
            }
            break;
        default:
            /* No extra input structure information to set. */
            break;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * DER certificate/CRL to object decoder context.
 */
typedef struct wp_Der2Obj {
    /** Provider context - used to read the core BIO. */
    WOLFPROV_CTX* provCtx;
} wp_Der2Obj;

/**
 * Create a new DER to object decoder context.
 *
 * @param [in] provCtx  Provider context.
 * @return  Pointer to context.
 */
static wp_Der2Obj* wp_der2obj_newctx(WOLFPROV_CTX* provCtx)
{
    wp_Der2Obj* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = (wp_Der2Obj*)OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }

    return ctx;
}

/**
 * Dispose of DER to object decoder context.
 *
 * @param [in] ctx  DER to object decoder context.
 */
static void wp_der2obj_freectx(wp_Der2Obj* ctx)
{
    OPENSSL_free(ctx);
}

/**
 * Length of the DER SEQUENCE at the start of the data.
 *
 * @param [in] data  DER data.
 * @param [in] len   Length of data in bytes.
 * @return  Length of the SEQUENCE including its header.
 * @return  0 when the data does not start with a complete DER SEQUENCE.
 */
static word32 wp_der2obj_seq_len(const unsigned char* data, word32 len)
{
    word32 hdrLen = 2;
    word32 contentLen = 0;
    word32 n;
    word32 i;

    if ((len < 2) || (data[0] != 0x30)) {
        return 0;
    }
    if (data[1] < 0x80) {
        contentLen = data[1];
    }
    else {
        n = data[1] & 0x7f;
        if ((n == 0) || (n > 4) || (len < 2 + n)) {
            return 0;
        }
        for (i = 0; i < n; i++) {
            contentLen = (contentLen << 8) | data[2 + i];
        }
        hdrLen += n;
    }
    if (contentLen > len - hdrLen) {
        return 0;
    }
    return hdrLen + contentLen;
}

/**
 * Pass DER data up as a certificate or CRL object, unparsed.
 *
 * The file store needs this for DER input, as OpenSSL's file store does
 * (file_store_any2obj.c): the PEM to DER decoder does the same for PEM input.
 * No cryptographic operation is performed.
 *
 * @param [in]      ctx        DER to object decoder context.
 * @param [in, out] coreBio    BIO wrapped for the core.
 * @param [in]      obj        Object type: OSSL_OBJECT_CERT or OSSL_OBJECT_CRL.
 * @param [in]      dataCb     Callback to pass the object to.
 * @param [in]      dataCbArg  Argument to pass to callback.
 * @return  1 on success or when the data is not a DER SEQUENCE.
 * @return  0 on failure.
 */
static int wp_der2obj_decode(wp_Der2Obj* ctx, OSSL_CORE_BIO* coreBio, int obj,
    OSSL_CALLBACK* dataCb, void* dataCbArg)
{
    int ok = 1;
    unsigned char* data = NULL;
    word32 len = 0;
    word32 objLen;
    OSSL_PARAM params[3];

    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_der2obj_decode");

    if (!wp_read_der_bio(ctx->provCtx, coreBio, &data, &len)) {
        ok = 0;
    }
    /* Not a DER SEQUENCE: not for this decoder, let others try. */
    else if ((objLen = wp_der2obj_seq_len(data, len)) != 0) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
            data, objLen);
        params[1] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &obj);
        params[2] = OSSL_PARAM_construct_end();
        ok = dataCb(params, dataCbArg);
    }
    OPENSSL_free(data);

    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decode DER certificate: pass it up as a certificate object.
 */
static int wp_der2cert_decode(wp_Der2Obj* ctx, OSSL_CORE_BIO* coreBio,
    int selection, OSSL_CALLBACK* dataCb, void* dataCbArg,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    (void)selection;
    (void)pwCb;
    (void)pwCbArg;
    return wp_der2obj_decode(ctx, coreBio, OSSL_OBJECT_CERT, dataCb,
        dataCbArg);
}

/**
 * Decode DER CRL: pass it up as a CRL object.
 */
static int wp_der2crl_decode(wp_Der2Obj* ctx, OSSL_CORE_BIO* coreBio,
    int selection, OSSL_CALLBACK* dataCb, void* dataCbArg,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    (void)selection;
    (void)pwCb;
    (void)pwCbArg;
    return wp_der2obj_decode(ctx, coreBio, OSSL_OBJECT_CRL, dataCb,
        dataCbArg);
}

/** Dispatch table for DER certificate to object decoder. */
const OSSL_DISPATCH wp_der_to_cert_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,  (DFUNC)wp_der2obj_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (DFUNC)wp_der2obj_freectx },
    { OSSL_FUNC_DECODER_DECODE,  (DFUNC)wp_der2cert_decode },
    { 0, NULL }
};

/** Dispatch table for DER CRL to object decoder. */
const OSSL_DISPATCH wp_der_to_crl_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,  (DFUNC)wp_der2obj_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (DFUNC)wp_der2obj_freectx },
    { OSSL_FUNC_DECODER_DECODE,  (DFUNC)wp_der2crl_decode },
    { 0, NULL }
};

/**
 * Information about supported decoders from file data.
 */
typedef struct wp_DecoderInfo {
    /* Name of format. */
    const char* name;
    /* Query property supported. */
    const char* propQuery;
} wp_DecoderInfo;

static const wp_DecoderInfo wp_decoders[] = {
#ifdef WP_HAVE_RSA
    { "RSA"    , "structure=SubjectPublicKeyInfo"    },
    { "RSA"    , "structure=PrivateKeyInfo"          },
#endif
#ifdef WP_HAVE_DH
    { "DH"     , "structure=type-specific"           },
    { "DH"     , "structure=SubjectPublicKeyInfo"    },
    { "DH"     , "structure=PrivateKeyInfo"          },
#endif
#ifdef WP_HAVE_ECC
    { "EC"     , "structure=type-specific"           },
    { "EC"     , "structure=SubjectPublicKeyInfo"    },
    { "EC"     , "structure=PrivateKeyInfo"          },
#endif
#ifdef WP_HAVE_X25519
    { "X25519" , "structure=SubjectPublicKeyInfo"    },
    { "X25519" , "structure=PrivateKeyInfo"          },
#endif
#ifdef WP_HAVE_ED25519
    { "ED25519", "structure=SubjectPublicKeyInfo"    },
    { "ED25519", "structure=PrivateKeyInfo"          },
#endif
#ifdef WP_HAVE_X448
    { "X448"   , "structure=SubjectPublicKeyInfo"    },
    { "X448"   , "structure=PrivateKeyInfo"          },
#endif
#ifdef WP_HAVE_ED448
    { "ED448"  , "structure=SubjectPublicKeyInfo"    },
    { "ED448"  , "structure=PrivateKeyInfo"          },
#endif
    { "der"    , NULL                                },
    { "der"    , "structure=EncryptedPrivateKeyInfo" },
};

/** Number of decoders supported. */
#define WP_DECODERS_SIZE  (sizeof(wp_decoders) / sizeof(*wp_decoders))

/**
 * Combine a decoder's structure query with the caller's property query.
 *
 * @param [in]  base    Structure property query. May be NULL.
 * @param [in]  caller  Caller's property query. May be NULL.
 * @param [out] query   Combined property query string, or NULL when neither
 *                      input constrains the fetch.
 * @return  1 on success.
 * @return  0 on allocation failure.
 */
static int wp_file_decoder_prop_query(const char* base, const char* caller,
    char** query)
{
    int ok = 1;
    size_t len;

    /* Treat an empty query string the same as an absent (NULL) one. */
    if ((base != NULL) && (*base == '\0')) {
        base = NULL;
    }
    if ((caller != NULL) && (*caller == '\0')) {
        caller = NULL;
    }

    *query = NULL;
    if (base == NULL) {
        if (caller != NULL) {
            *query = OPENSSL_strdup(caller);
            ok = (*query != NULL);
        }
    }
    else if (caller == NULL) {
        *query = OPENSSL_strdup(base);
        ok = (*query != NULL);
    }
    else {
        len = XSTRLEN(base) + XSTRLEN(caller) + 2;
        *query = OPENSSL_malloc(len);
        if (*query == NULL) {
            ok = 0;
        }
        else {
            XSNPRINTF(*query, len, "%s,%s", base, caller);
        }
    }

    return ok;
}

/**
 * Fetch a decoder and add it to the decoder context.
 *
 * @param [in]      ctx        File system context object.
 * @param [in, out] decCtx     OpenSSL decoder context.
 * @param [in]      name       Decoder name.
 * @param [in]      propQuery  Structure property query. May be NULL.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_file_add_decoder(wp_FileCtx* ctx, OSSL_DECODER_CTX* decCtx,
    const char* name, const char* propQuery)
{
    int ok = 1;
    OSSL_DECODER* decoder = NULL;
    char* query = NULL;

    if (!wp_file_decoder_prop_query(propQuery, ctx->propQuery, &query)) {
        ok = 0;
    }
    if (ok) {
        decoder = OSSL_DECODER_fetch(ctx->provCtx->libCtx, name, query);
        if (decoder == NULL) {
            ok = 0;
        }
    }
    if (ok && !OSSL_DECODER_CTX_add_decoder(decCtx, decoder)) {
        ok = 0;
    }
    OSSL_DECODER_free(decoder);
    OPENSSL_free(query);

    return ok;
}

/**
 * Set the decoders into the decoder context.
 *
 * @param [in]      ctx     File system context object.
 * @param [in, out] decCtx  OpenSSL decoder context.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_file_set_decoder(wp_FileCtx* ctx, OSSL_DECODER_CTX* decCtx)
{
    int ok = 1;
    size_t i;

    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_file_set_decoder");

    for (i = 0; ok && (i < WP_DECODERS_SIZE); i++) {
        ok = wp_file_add_decoder(ctx, decCtx, wp_decoders[i].name,
            wp_decoders[i].propQuery);
    }
    /* DER certificates and CRLs are passed up unparsed, as OpenSSL's file
     * store does. Only added when one is expected: key loading is unchanged. */
    if (ok && (ctx->type == OSSL_STORE_INFO_CERT)) {
        ok = wp_file_add_decoder(ctx, decCtx, WP_NAMES_DER2OBJ,
            "structure=Certificate");
    }
    else if (ok && (ctx->type == OSSL_STORE_INFO_CRL)) {
        ok = wp_file_add_decoder(ctx, decCtx, WP_NAMES_DER2OBJ,
            "structure=CertificateList");
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Setup a decoder with the decoders supported.
 *
 * @param [in, out] ctx  File system context object.
 * @return  Decoder context object on success.
 * @return  NULL on failure.
 */
static OSSL_DECODER_CTX* wp_file_setup_decoders(wp_FileCtx* ctx)
{
    int ok = 1;
    OSSL_DECODER_CTX* decCtx;

    decCtx = OSSL_DECODER_CTX_new();
    if (decCtx == NULL) {
        ok = 0;
    }
    if (ok && !OSSL_DECODER_CTX_set_input_type(decCtx, ctx->format)) {
        ok = 0;
    }
    if (ok && !wp_file_decoder_set_input_structure(decCtx, ctx->type)) {
        ok = 0;
    }
    if (ok && !wp_file_set_decoder(ctx, decCtx)) {
        ok = 0;
    }
    if (ok && (!OSSL_DECODER_CTX_add_extra(decCtx, ctx->provCtx->libCtx,
            ctx->propQuery))) {
        ok = 0;
    }
    if (ok && !OSSL_DECODER_CTX_set_construct(decCtx,
            (OSSL_DECODER_CONSTRUCT*)&wp_file_load_construct)) {
        ok = 0;
    }
    if (ok && !OSSL_DECODER_CTX_set_cleanup(decCtx,
            (OSSL_DECODER_CLEANUP*)&wp_file_load_cleanup)) {
        ok = 0;
    }

    if (!ok) {
        OSSL_DECODER_CTX_free(decCtx);
        decCtx = NULL;
    }

    return decCtx;
}

static void wp_bio_consume_all(BIO* bio)
{
    char buffer[128];
    int bytes_read = 0;

    /* Consume everything */
    do {
        bytes_read = BIO_read(bio, buffer, sizeof(buffer));
    } while (bytes_read > 0);

    /* buffer may hold private key material from the drained file. */
    OPENSSL_cleanse(buffer, sizeof(buffer));
}

/**
 * Load the data from a file.
 *
 * @param [in, out] ctx       File system context object.
 * @param [in]      objCb     Object callback.
 * @param [in]      objCbArg  Argument to pass to object callback.
 * @param [in]      pwCb      Password callback.
 * @param [in]      pwCbArg   Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_file_load(wp_FileCtx* ctx, OSSL_CALLBACK* objCb, void* objCbArg,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_file_load");

    if (ctx->decCtx == NULL) {
        ctx->decCtx = wp_file_setup_decoders(ctx);
    }
    if (ctx->decCtx == NULL) {
        ok = 0;
        /* If we error here, we dont consume the BIO at all and simply return 0,
         * however callers loop is until EOF. Set BIO to EOF on early error */
         wp_bio_consume_all(ctx->bio);
    }

    if (ok) {
        wp_FileLoadData data = { objCb, objCbArg };

        OSSL_DECODER_CTX_set_construct_data(ctx->decCtx, &data);
        OSSL_DECODER_CTX_set_passphrase_cb(ctx->decCtx, pwCb, pwCbArg);

        if (!OSSL_DECODER_from_bio(ctx->decCtx, ctx->bio)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check for End Of File.
 *
 * @param [in] ctx  File system context object.
 * @return  1 when at end of file.
 * @return  0 when not at end of file.
 */
static int wp_file_eof(wp_FileCtx* ctx)
{
    return BIO_eof(ctx->bio);
}

/**
 * Close the file.
 *
 * Disposes of the file system context object.
 *
 * @param [in, out] ctx  File system context object.
 * @return  1 on success.
 */
static int wp_file_close(wp_FileCtx* ctx)
{
    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_file_close");

    wp_filectx_free(ctx);
    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

/** Dispatch table for file store. */
const OSSL_DISPATCH wp_file_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN,                (DFUNC)wp_file_open                },
    { OSSL_FUNC_STORE_ATTACH,              (DFUNC)wp_file_attach              },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (DFUNC)wp_file_settable_ctx_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS,      (DFUNC)wp_file_set_ctx_params      },
    { OSSL_FUNC_STORE_LOAD,                (DFUNC)wp_file_load                },
    { OSSL_FUNC_STORE_EOF,                 (DFUNC)wp_file_eof                 },
    { OSSL_FUNC_STORE_CLOSE,               (DFUNC)wp_file_close               },
    { 0, NULL },
};


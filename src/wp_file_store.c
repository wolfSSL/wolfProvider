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

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

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
    OSSL_DECODER* decoder;

    for (i = 0; ok && (i < WP_DECODERS_SIZE); i++) {
        decoder = OSSL_DECODER_fetch(ctx->provCtx->libCtx, wp_decoders[i].name,
            wp_decoders[i].propQuery);
        if (decoder == NULL) {
            ok = 0;
        }
        if (ok && !OSSL_DECODER_CTX_add_decoder(decCtx, decoder)) {
            ok = 0;
        }
        OSSL_DECODER_free(decoder);
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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

    if (ctx->decCtx == NULL) {
        ctx->decCtx = wp_file_setup_decoders(ctx);
    }
    if (ctx->decCtx == NULL) {
        ok = 0;
    }

    if (ok) {
        wp_FileLoadData data = { objCb, objCbArg };

        OSSL_DECODER_CTX_set_construct_data(ctx->decCtx, &data);
        OSSL_DECODER_CTX_set_passphrase_cb(ctx->decCtx, pwCb, pwCbArg);

        if (!OSSL_DECODER_from_bio(ctx->decCtx, ctx->bio)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
    wp_filectx_free(ctx);
    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
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


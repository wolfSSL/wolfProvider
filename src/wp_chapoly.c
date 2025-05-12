/* Dispatch functions for wp_chacha20_poly1305 cipher */

#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

#define CHACHA20_POLY1305_AEAD_INITIAL_COUNTER  0

#define CHACHA_U8TOU32(p)  ( \
    ((unsigned int)(p)[0])     | ((unsigned int)(p)[1]<<8) | \
    ((unsigned int)(p)[2]<<16) | ((unsigned int)(p)[3]<<24)  )

// include all define and declaration here, cuz there is no wp_xxx.h ? and no chacha or poly for wp ?
#define POLY1305_BLOCK_SIZE  16
#define CHACHA_CTR_SIZE 16

/** 
 * Authenticated Encryption with Associated Data structure.
 */
typedef struct wp_CP_AeadCtx {
    ChaChaPoly_Aead ChaChaPoly_Aead;

    /** Provider context that we are constructed from. */
    WOLFPROV_CTX* provCtx;

    /** Cipher mode: chacha20_poly1305 */
    int mode;

    /** Length of key. */
    size_t keyLen;
    /** Length of iv/nonce. */
    size_t ivLen;
    /** Authentication tag length.  */
    size_t tagLen;
    /** TLS additional authentication data size. */
    size_t tlsAadLen;
    /** TLS pad size. */
    size_t tlsAadPadSz;

    /** Initialized for encryption or decryption. */
    unsigned int enc:1;
    /** AAD set with call to update. */
    unsigned int aadSet:1;
    unsigned int ivSet:1;
    unsigned int keySet:1;

    /** IV/nonce data. */
    unsigned char iv[CHACHA20_POLY1305_AEAD_IV_SIZE];
    unsigned int nonce[12 / 4];
    unsigned char key[CHACHA20_POLY1305_AEAD_KEYSIZE];
    /** Buffer to hold tag. */
    unsigned char tag[POLY1305_BLOCK_SIZE];
    /** Buffer to hold TLS AAD. */
    unsigned char tls_aad[POLY1305_BLOCK_SIZE];

    struct { uint64_t aad, text; } len;
    
    unsigned int mac_inited : 1; // to remove

} wp_CP_AeadCtx;


/** Uninitialized value for a field of type size_t. */
#define UNINITIALISED_SIZET      ((size_t)-1)

#define WP_CHACHA20_POLY1305_BLKLEN 1
#define WP_CHACHA20_POLY1305_MAX_IVLEN 12
#define WP_CHACHA20_POLY1305_MODE 0
/** AEAD cipher flags. */
#define WP_CHACHA20_POLY1305_AEAD_FLAGS (WP_CIPHER_FLAG_AEAD                         \
                                 | WP_CIPHER_FLAG_CUSTOM_IV)

static OSSL_FUNC_cipher_newctx_fn wp_chacha20_poly1305_newctx;
static OSSL_FUNC_cipher_freectx_fn wp_chacha20_poly1305_freectx;
static OSSL_FUNC_cipher_dupctx_fn wp_chacha20_poly1305_dupctx;
static OSSL_FUNC_cipher_encrypt_init_fn wp_chacha20_poly1305_einit;
static OSSL_FUNC_cipher_decrypt_init_fn wp_chacha20_poly1305_dinit;
static OSSL_FUNC_cipher_get_params_fn wp_chacha20_poly1305_get_params;
static OSSL_FUNC_cipher_get_ctx_params_fn wp_chacha20_poly1305_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn wp_chacha20_poly1305_set_ctx_params;
static OSSL_FUNC_cipher_cipher_fn wp_chacha20_poly1305_cipher;
static OSSL_FUNC_cipher_final_fn wp_chacha20_poly1305_final;
static OSSL_FUNC_cipher_gettable_ctx_params_fn wp_chacha20_poly1305_gettable_ctx_params;

#define wp_chacha20_poly1305_settable_ctx_params wp_cp_aead_settable_ctx_params
#define wp_chacha20_poly1305_gettable_params wp_cp_aead_gettable_params    
#define wp_chacha20_poly1305_update wp_chacha20_poly1305_cipher

/**
 * Initialize AEAD cipher for use with TLS. Return extra padding (tag length).
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      aad     Additional authentication data.
 * @param [in]      aadLen  Length of AAD in bytes.
 * @return  Length of extra padding in bytes on success.
 * @return  0 on failure.
 */
static int wp_cp_aead_tls_init(wp_CP_AeadCtx* ctx, unsigned char* aad, size_t aadLen)
{
    WOLFPROV_MSG(WP_LOG_PK,"called wp_cp_aead_tls_init");
    int ok = 1;
    size_t len = 0;
    
    size_t tagLen = POLY1305_BLOCK_SIZE;

    if (!wolfssl_prov_is_running()) {
       ok = 0;
    }
    if (aadLen != EVP_AEAD_TLS1_AAD_LEN) {
       ok = 0;
    }

    if (ok) {
        /* Cache AAD. */
        XMEMCPY(ctx->tls_aad, aad, EVP_AEAD_TLS1_AAD_LEN); //XMEMCPY(buf, aad, aadLen);
        ctx->tlsAadLen = aadLen;

        len = aad[EVP_AEAD_TLS1_AAD_LEN - 2] << 8 | aad[EVP_AEAD_TLS1_AAD_LEN - 1];
        if (len >= POLY1305_BLOCK_SIZE ) { //EVP_AEAD_TLS_EXPLICIT_IV_LEN = 8
            len -= POLY1305_BLOCK_SIZE;
        }
        else { // len < POLY1305_BLOCK_SIZE
            ok = 0;
        }
    }
    
    if (ok ) {
        if (!ctx->enc) { /* If decrypting, correct for tag too. */
            if (len < tagLen) {
                ok = 0;
            }
            if (ok) {
                len -= tagLen; /* discount attached tag */
                aad[aadLen - 2] = (unsigned char)(len >> 8);
                aad[aadLen - 1] = (unsigned char)(len & 0xff);
            }
        }
        ctx->tlsAadLen = len;

        // AEAD_CHACHA20_POLY1305 requires a 96-bit nonce, which is formed as follows:
        // 1.  The 64-bit record sequence number is serialized as an 8-byte,
        //     big-endian value and padded on the left with four 0x00 bytes. 
        // 2.  The padded sequence number is XORed with the client_write_IV
        //     (when the client is sending) or server_write_IV (when the server is sending).
        // the |counter| argument is pointer to concatenated nonce and counter values collected into 4 32-bit elements.

        /* merge record sequence number as per RFC7905 */
        ctx->ChaChaPoly_Aead.chacha.X[1] = ctx->nonce[0];
        ctx->ChaChaPoly_Aead.chacha.X[2] = ctx->nonce[1] ^ CHACHA_U8TOU32(aad);
        ctx->ChaChaPoly_Aead.chacha.X[3] = ctx->nonce[2] ^ CHACHA_U8TOU32(aad+4);

        ctx->mac_inited = 0;
        /**
          * IV(nonce) changes with each record
          * counter is for what value the block counter should start ... usually 0
          */
        // assume iv set? and then merge records. otherwise non-set iv merge is pointless?
        // tls-init with aad info: store aad val in the ctx for later use. 
        // same as tls-set-fixed-iv, all only matters after aead init complete?
    }

    if (!ok) {
        tagLen = 0;
    }
    /* Extra padding: tag appended to record. */
    return (int)tagLen;
}

/**
 * Set the fixed nonce for ChaChaPoly cipher.
 *
 * @param [in, out] ctx  AEAD context object.
 * @param [in]      iv   Fixed part of IV/nonce.
 * @param [in]      len  Length of fixed part.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_cp_aead_tls_iv_set_fixed(wp_CP_AeadCtx* ctx, unsigned char* fixed, size_t flen) 
{
    WOLFPROV_MSG(WP_LOG_PK,"called wp_cp_aead_tls_ivSet_fixed");
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    
    if (flen != CHACHA20_POLY1305_AEAD_IV_SIZE) {
        ok = 0;
    }

    if (ok) {
        // check key init status first ? no one is checking?
        ctx->nonce[0] = ctx->ChaChaPoly_Aead.chacha.X[1] = CHACHA_U8TOU32(fixed); //LITTLE32(fixed);
        ctx->nonce[1] = ctx->ChaChaPoly_Aead.chacha.X[2] = CHACHA_U8TOU32(fixed + 4); //LITTLE32(fixed + 4);
        ctx->nonce[2] = ctx->ChaChaPoly_Aead.chacha.X[3] = CHACHA_U8TOU32(fixed + 8);//LITTLE32(fixed + 8);
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return an array of supported gettable parameters for the AEAD cipher.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM *wp_cp_aead_gettable_params(WOLFPROV_CTX* provCtx)
{
    /**
     * Supported gettable parameters for AEAD cipher.
     */
    static const OSSL_PARAM wp_cp_aead_supported_gettable_params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_cp_aead_supported_gettable_params;
}

/**
 * Get the AEAD cipher parameters.
 *
 * @param [in, out] params   Array of parameters and values.
 * @param [in]      md       Message digest id.
 * @param [in]      flags    Flags of cipher.
 * @param [in]      keyBits  Size of key in bits.
 * @param [in]      blkBits  Size of block in bits.
 * @param [in]      ivBits   Size of IV/nonce in bits.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_cp_aead_get_params(OSSL_PARAM params[], unsigned int md,
     uint64_t flags, size_t keyBits, size_t blkBits, size_t ivBits)
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if ((p != NULL) && (!OSSL_PARAM_set_uint(p, md))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_int(p, (flags & WP_CIPHER_FLAG_AEAD) != 0))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_int(p, (flags & WP_CIPHER_FLAG_CUSTOM_IV) != 0))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_int(p, (flags & WP_CIPHER_FLAG_RAND_KEY) != 0))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, keyBits / 8))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, blkBits / 8))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, ivBits / 8))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return an array of supported settable parameters for the AEAD context.
 *
 * @param [in] ctx      AEAD context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM *wp_cp_aead_settable_ctx_params(wp_CP_AeadCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported settable parameters for AEAD context.
     */
    static const OSSL_PARAM wp_cp_aead_supported_settable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_cp_aead_supported_settable_ctx_params;
}

/**
 * Create a new AEAD context object for performing CHACHA20_POLY1305.
 *
 * @return  NULL on failure.
 * @return  AEAD context object on success.
 */
static void *wp_chacha20_poly1305_newctx(void *provctx) 
{
    WOLFPROV_MSG(WP_LOG_PK,"called wp_chacha20_poly1305_newctx");

    wp_CP_AeadCtx *ctx = NULL;

    (void)provctx;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->keyLen = CHACHA20_POLY1305_AEAD_KEYSIZE; // new define or use wssldef ? OSSL ONLY HAS PROV DEFINES
        ctx->ivLen = CHACHA20_POLY1305_AEAD_IV_SIZE; // TLS_EXPLICIT_IV_LEN ???
        ctx->mode = WP_CHACHA20_POLY1305_MODE;
        ctx->tagLen = UNINITIALISED_SIZET;

        // ossl from chacha20_poly1305_initkey || chacha20_poly1305_initiv
        ctx->len.aad = 0;
        ctx->len.text = 0;
        ctx->aadSet = 0;
        ctx->mac_inited = 0;
        ctx->tlsAadLen = UNINITIALISED_SIZET; // must
        memset(ctx->tls_aad, 0, POLY1305_BLOCK_SIZE);
    }
    return ctx;
}

static void *wp_chacha20_poly1305_dupctx(void *provctx)
{
    WOLFPROV_MSG(WP_LOG_PK,"called wp_chacha20_poly1305_dupctx");
    wp_CP_AeadCtx *ctx = provctx;
    wp_CP_AeadCtx *dctx = NULL;

    if (ctx == NULL)
        return NULL;
    dctx = OPENSSL_memdup(ctx, sizeof(*ctx));
    
    return dctx;
}

static void wp_chacha20_poly1305_freectx(void *vctx)
{
    WOLFPROV_MSG(WP_LOG_PK,"called wp_chacha20_poly1305_freectx");
    wp_CP_AeadCtx *ctx = (wp_CP_AeadCtx *)vctx;

    if (ctx != NULL) {
        /* reset and cleanup sensitive context */
        memset(&ctx->ChaChaPoly_Aead, 0, sizeof(ChaChaPoly_Aead));
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

static int wp_chacha20_poly1305_get_params(OSSL_PARAM params[])
{
    WOLFPROV_MSG(WP_LOG_PK,"called wp_chacha20_poly1305_get_params");
    return wp_cp_aead_get_params(params, 0, WP_CHACHA20_POLY1305_AEAD_FLAGS,
                                            CHACHA20_POLY1305_AEAD_KEYSIZE * 8,
                                            WP_CHACHA20_POLY1305_BLKLEN * 8,
                                            CHACHA20_POLY1305_AEAD_IV_SIZE * 8);
}

static int wp_chacha20_poly1305_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    WOLFPROV_MSG(WP_LOG_PK,"called wp_chacha20_poly1305_get_ctx_params");

    wp_CP_AeadCtx *ctx = (wp_CP_AeadCtx *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, CHACHA20_POLY1305_AEAD_IV_SIZE)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        WOLFPROV_MSG(WP_LOG_PK,"get_ctx_params: IVLEN ");
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL ) {
        if (!OSSL_PARAM_set_size_t(p, CHACHA20_POLY1305_AEAD_KEYSIZE)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        WOLFPROV_MSG(WP_LOG_PK,"get_ctx_params: KEYLEN ");
    }
    
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, ctx->tagLen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        WOLFPROV_MSG(WP_LOG_PK,"get_ctx_params: tagLEN ");
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL ) {
        if (!OSSL_PARAM_set_size_t(p, ctx->tlsAadPadSz)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        WOLFPROV_MSG(WP_LOG_PK,"get_ctx_params: aad pad ");
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        if (!ctx->enc) {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return 0;
        }
        if (p->data_size == 0 || p->data_size > POLY1305_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        memcpy(p->data, ctx->tag, p->data_size);
        WOLFPROV_MSG(WP_LOG_PK,"get_ctx_params: tag ");
    }

    return 1;
}

static const OSSL_PARAM wp_chacha20_poly1305_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *wp_chacha20_poly1305_gettable_ctx_params
    (ossl_unused void *cctx, ossl_unused void *provctx)
{
    WOLFPROV_MSG(WP_LOG_PK,"called wp_chacha20_poly1305_gettable_ctx_params");
    return wp_chacha20_poly1305_known_gettable_ctx_params;
}

static int wp_chacha20_poly1305_set_ctx_params(void *vctx, const OSSL_PARAM params[]) //*******temp unused void */
{
    WOLFPROV_MSG(WP_LOG_PK,"called wp_chacha20_poly1305_set_ctx_params");
    const OSSL_PARAM *p;
    size_t len = 0;
    wp_CP_AeadCtx *ctx = (wp_CP_AeadCtx *)vctx;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != CHACHA20_POLY1305_AEAD_KEYSIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        WOLFPROV_MSG(WP_LOG_PK,"done setting keylen len=%ld", len);
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != WP_CHACHA20_POLY1305_MAX_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        WOLFPROV_MSG(WP_LOG_PK,"done setting ivlen len=%ld", len);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (p->data_size == 0 || p->data_size > POLY1305_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        if (p->data != NULL) {
            if (ctx->enc) { 
                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_NEEDED);
                return 0;
            }
            memcpy(ctx->tag, p->data, p->data_size);
        }
        ctx->tagLen = p->data_size;
        WOLFPROV_MSG(WP_LOG_PK,"done setting AEAD_TAG len=%ld", ctx->tagLen);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        
        WOLFPROV_MSG(WP_LOG_PK,"located aad");
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        len = wp_cp_aead_tls_init(ctx, (unsigned char*)p->data, (size_t)p->data_size);
        if (len == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return 0;
        }
        ctx->tlsAadPadSz = len;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL) {
        WOLFPROV_MSG(WP_LOG_PK,"located TLS1_IV_FIXED");
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        if (!wp_cp_aead_tls_iv_set_fixed(ctx, (unsigned char*)p->data, (size_t)p->data_size)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
    }
    /* ignore OSSL_CIPHER_PARAM_AEAD_MAC_KEY */

    return 1;
}

/**
 * Initialize CHACHA20_POLY1305 cipher for encryption.
 *
 * Sets the parameters as well as key and IV/nonce.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      key     Private key to initialize with. May be NULL.
 * @param [in]      keyLen  Length of key in bytes.
 * @param [in]      iv      IV/nonce to initialize with. May be NULL.
 * @param [in]      ivLen   Length of IV/nonce in bytes.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_chacha20_poly1305_einit(void *vctx, const unsigned char *key,
                                  size_t keyLen, const unsigned char *iv,
                                  size_t ivLen, const OSSL_PARAM params[])
{
    WOLFPROV_MSG(WP_LOG_PK,"called wp_chacha20_poly1305_einit");
    wp_CP_AeadCtx *ctx = (wp_CP_AeadCtx *)vctx;
    int ok = 1;
    int rc = 0;

    if (!wolfssl_prov_is_running()) {
        return 0;
    }
    WOLFPROV_MSG(WP_LOG_PK,"yes running");

    if(key == NULL) {
        WOLFPROV_MSG(WP_LOG_PK,"key == NULL");
    }
    if(iv == NULL) {
        WOLFPROV_MSG(WP_LOG_PK,"iv == NULL");
    }
    //WOLFPROV_MSG(WP_LOG_PK," keylen= %ld", keyLen);
    //WOLFPROV_MSG(WP_LOG_PK," ivlen= %ld", ivLen);

    if (key) {
        if (keyLen == 0 || keyLen != CHACHA20_POLY1305_AEAD_KEYSIZE) {
            ok = 0;
        }
        if (ok) { 
            // cache user key
            XMEMCPY(ctx->key, key, keyLen);   
            ctx->keySet = 1;
        }
        //WOLFPROV_MSG(WP_LOG_PK," cache key_Init ok= %d", ok);
    }

    if (iv) {
        if (ivLen == 0 || ivLen != CHACHA20_POLY1305_AEAD_IV_SIZE) {
            ok = 0;
        }
        if (ok) {   
            // cache iv
            XMEMCPY(ctx->iv, iv, ivLen);   
            ctx->ivSet = 1;
        }  
        //WOLFPROV_MSG(WP_LOG_PK," cache iv_Init ok= %d", ok);
    }
    
    if (ctx->ivSet && ctx->keySet) {
        rc = wc_ChaCha20Poly1305_Init(&ctx->ChaChaPoly_Aead, 
                                                    (const byte*)ctx->key, 
                                                    (const byte*)ctx->iv, 
                                                    CHACHA20_POLY1305_AEAD_ENCRYPT);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            // set ctx nonce val
            ctx->nonce[0] = ctx->ChaChaPoly_Aead.chacha.X[1];
            ctx->nonce[1] = ctx->ChaChaPoly_Aead.chacha.X[2];
            ctx->nonce[2] = ctx->ChaChaPoly_Aead.chacha.X[3];
            // ctx->ivSet = 1;
            ctx->mac_inited = 1;
        }
        //WOLFPROV_MSG(WP_LOG_PK," wc_ChaCha20Poly1305_Init ok= %d", ok);   
    }

    if (ok) {
        ctx->enc = 1; // CHACHA20_POLY1305_AEAD_ENCRYPT
        ctx->tlsAadLen = UNINITIALISED_SIZET;

        ok = wp_chacha20_poly1305_set_ctx_params(ctx, params); 
    }   

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}


/**
 * Initialize CHACHA20_POLY1305 cipher for decryption.
 *
 * Sets the parameters as well as key and IV/nonce.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      key     Private key to initialize with. May be NULL.
 * @param [in]      keyLen  Length of key in bytes.
 * @param [in]      iv      IV/nonce to initialize with. May be NULL.
 * @param [in]      ivLen   Length of IV/nonce in bytes.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_chacha20_poly1305_dinit(void *vctx, const unsigned char *key,
                                        size_t keyLen, const unsigned char *iv,
                                        size_t ivLen, const OSSL_PARAM params[])
{
    WOLFPROV_MSG(WP_LOG_PK,"called wp_chacha20_poly1305_dinit");
    wp_CP_AeadCtx *ctx = (wp_CP_AeadCtx *)vctx;
    int ok = 1;
    int rc = 0;

    if (!wolfssl_prov_is_running()) {
       return 0;
    }

    if(key == NULL) {
        WOLFPROV_MSG(WP_LOG_PK,"D key == NULL");
    }
    if(iv == NULL) {
        WOLFPROV_MSG(WP_LOG_PK,"D iv == NULL");
    }
    //WOLFPROV_MSG(WP_LOG_PK,"D keylen= %ld", keyLen);
    //WOLFPROV_MSG(WP_LOG_PK,"D ivlen= %ld", ivLen);
    if (key) {
        if (keyLen == 0 || keyLen != CHACHA20_POLY1305_AEAD_KEYSIZE) {
            ok = 0;
        }
        if (ok) { 
            // cache user key
            XMEMCPY(ctx->key, key, keyLen);   
            ctx->keySet = 1;
        }
        //WOLFPROV_MSG(WP_LOG_PK," cache key_Init ok= %d", ok);
    }

    if (iv) {
        if (ivLen == 0 || ivLen != CHACHA20_POLY1305_AEAD_IV_SIZE) {
            ok = 0;
        }
        if (ok) {   
            // cache iv
            XMEMCPY(ctx->iv, iv, ivLen);   
            ctx->ivSet = 1;
        }  
        //WOLFPROV_MSG(WP_LOG_PK," cache iv_Init ok= %d", ok);
    }
    
    if (ctx->ivSet && ctx->keySet) {
        rc = wc_ChaCha20Poly1305_Init(&ctx->ChaChaPoly_Aead, 
                                                    (const byte*)ctx->key, 
                                                    (const byte*)ctx->iv, 
                                                    CHACHA20_POLY1305_AEAD_DECRYPT);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            // set ctx nonce val
            ctx->nonce[0] = ctx->ChaChaPoly_Aead.chacha.X[1];
            ctx->nonce[1] = ctx->ChaChaPoly_Aead.chacha.X[2];
            ctx->nonce[2] = ctx->ChaChaPoly_Aead.chacha.X[3];
            // ctx->ivSet = 1;
            ctx->mac_inited = 1;
        }
        //WOLFPROV_MSG(WP_LOG_PK," wc_ChaCha20Poly1305_Init ok= %d", ok);   
    }

    if (ok) {
        ctx->enc = 0; // CHACHA20_POLY1305_AEAD_DECRYPT
        ctx->tlsAadLen = UNINITIALISED_SIZET;

        ok = wp_chacha20_poly1305_set_ctx_params(ctx, params); 
    }   
   
    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Cipher update for CHACHA20_POLY1305_AEAD.
 *
 * @param [in, out] ctx      AEAD context object.
 * @param [out]     out      Buffer to hold encrypted/decrypted data.
 * @param [out]     outLen   Length of data in output buffer.
 * @param [in]      outSize  Size of output buffer in bytes.
 * @param [in]      in       Data to be encrypted/decrypted.
 * @param [in]      inLen    Length of data to be encrypted/decrypted.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_chacha20_poly1305_cipher(void *vctx, unsigned char *out,
                                    size_t *outLen, size_t outSize, 
                                    const unsigned char *in, size_t inLen)
{
    WOLFPROV_MSG(WP_LOG_PK,"called wp_chacha20_poly1305_cipher");
    wp_CP_AeadCtx *ctx = (wp_CP_AeadCtx *)vctx;
    int ok = 1;
    int ret = 0;
    int oLen = 0;

    if (!wolfssl_prov_is_running()) {
        return 0;
    }

    if (inLen == 0) { 
        *outLen = 0;
        return 1;
    }

    if (outSize < inLen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (ctx->tlsAadLen != UNINITIALISED_SIZET) {
        //if (inLen != ctx->tlsAadLen + POLY1305_BLOCK_SIZE) { // aadLen + 16 return 0; // ok = 0;
        WOLFPROV_MSG(WP_LOG_PK," not implemented");
#if 0
        if (out == NULL) {
            if (in == NULL) {
                ret = wc_ChaCha20Poly1305_UpdateAad(&ctx->ChaChaPoly_Aead, (const byte*)ctx->tls_aad, (word32)ctx->tlsAadLen);
                oLen = (word32)inLen; //inlen == 0
            }
            else {
                // buf[ctx->tlsAadLen+inlen]
                //ret = wc_ChaCha20Poly1305_UpdateAad(&ctx->ChaChaPoly_Aead, (const byte*)ctx->tls_aad+in, (word32)ctx->tlsAadLen+inlen);
                oLen = (word32)inLen;
            }
        }
        else {
            ret = wc_ChaCha20Poly1305_UpdateAad(&ctx->ChaChaPoly_Aead, (const byte*)ctx->tls_aad, (word32)ctx->tlsAadLen);

            ret = wc_ChaCha20Poly1305_UpdateData(&ctx->ChaChaPoly_Aead, (const byte*)in, (byte*)out, (word32)inLen);
            oLen = (word32)inLen;
        }
#endif
    }
    else { // non-tls

        if ((out == NULL) && (in == NULL)) {
            /* Nothing to do. */
            oLen = (word32)inLen;
        }
        else if ((out == NULL) && (in != NULL)) {
            /* AAD only. */
            ret = wc_ChaCha20Poly1305_UpdateAad(&ctx->ChaChaPoly_Aead, (const byte*)in, (word32)inLen);
            if (ret != 0) {
                ok = 0;
            }
            //WOLFPROV_MSG(WP_LOG_PK,"done wc_ChaCha20Poly1305_UpdateAad ok=%d", ok);
            if (ok) {
                // ctx->len.aad += inLen; ctx->ChaChaPoly_Aead UPDATED
                ctx->aadSet = 1;
                oLen = (word32)inLen;
            }
        }
        else if (outSize < inLen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            ok = 0;
        }
        else if (inLen > 0) { // out not null, in not null, inlen valid
            ret = wc_ChaCha20Poly1305_UpdateData(&ctx->ChaChaPoly_Aead, (const byte*)in, (byte*)out, (word32)inLen);
            if (ret != 0) {
                ok = 0;
            }
            if (ok) {
                oLen = (word32)inLen; //->ChaChaPoly_Aead.dataLen;
            }
            //WOLFPROV_MSG(WP_LOG_PK,"done wc_ChaCha20Poly1305_UpdateData ok=%d", ok);

        }

        *outLen = oLen;
    }
#if 0
    // chacha20_poly1305_not inited (poly auth key not created)
    //if (!ctx->mac_inited) { // or aead state not ready, COULD IGNORE
    
    // tls operation: tlsAadLen set by tls-init(aad updated) and expect output
    if (ctx->tlsAadLen != UNINITIALISED_SIZET) {
        if (out != NULL) { 
            
            if (inLen != ctx->tlsAadLen + POLY1305_BLOCK_SIZE) { // aadLen + 16
                return 0; // ok = 0;
            }
            // ossl: return chacha20_poly1305_tls_cipher(bctx, out, outl, in, inl);
            // inited + update aad + update data + final
            // update add + update data(encdec)

                // tls-init: just store aad val in ctx, dont merge other stuff ?
            
            ret = wc_ChaCha20Poly1305_UpdateAad(&ctx->ChaChaPoly_Aead, (const byte*)ctx->tls_aad, (word32)ctx->tlsAadLen);
            if (ret != 0) {
                ok = 0;
            }
            if (ok) {
                ctx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
                ctx->aadSet = 1;
                oLen = (word32)ctx->tlsAadLen;
            }
            WOLFPROV_MSG(WP_LOG_PK,"ctx->tlsAadLen: done wc_ChaCha20Poly1305_UpdateAad ok=%d", ok);
            ret = wc_ChaCha20Poly1305_UpdateData(&ctx->ChaChaPoly_Aead, (const byte*)in, (byte*)out, (word32)inLen);
            if (ret != 0) {
                ok = 0;
                oLen = ctx->ChaChaPoly_Aead.dataLen;
            }
            WOLFPROV_MSG(WP_LOG_PK,"ctx->tlsAadLen: done wc_ChaCha20Poly1305_UpdateData ok=%d", ok);
        }
        else {
             // tls operation not set (by tls-init(aad updated)) OR not expect output (update aad only)
            // aad not set yet (not from params, no output indicates set here)
            // check aead state ? (already checked iniside wc_ChaCha20Poly1305_UpdateAad)
            ret = wc_ChaCha20Poly1305_UpdateAad(&ctx->ChaChaPoly_Aead, (const byte*)ctx->tls_aad, (word32)EVP_AEAD_TLS1_AAD_LEN); // ctx->tlsAadLen
            if (ret != 0) {
                ok = 0;
            }
            if (ok) {
                ctx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
                ctx->aadSet = 1;
                oLen = (word32)ctx->tlsAadLen;
            }
            WOLFPROV_MSG(WP_LOG_PK,"ctx->tlsAadLen: done wc_ChaCha20Poly1305_UpdateAad ok=%d", ok);
        }
    }
#endif

    //else {
    //    WOLFPROV_MSG(WP_LOG_PK,"ready for tls cipher, ctx->tlsAadLen != UNINITIALISED_SIZET");
    //    //  ok = wp_aesgcm_tls_cipher(ctx, out, outLen, in, inLen);
    //    // call enc/dec directly?
    //}

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Cipher final for CHACHA20_POLY1305.
 *
 * @param [in, out] vctx     AEAD context object.
 * @param [out]     out      Buffer to hold encrypted/decrypted data.
 * @param [out]     outLen   Length of data in output buffer.
 * @param [in]      outSize  Size of output buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_chacha20_poly1305_final(void *vctx, unsigned char *out, size_t *outl,
                                   size_t outsize)
{
    WOLFPROV_MSG(WP_LOG_PK,"called wp_chacha20_poly1305_final");
    wp_CP_AeadCtx *ctx = (wp_CP_AeadCtx *)vctx;
    int ok = 1;
    int ret = 0;

    //WOLFPROV_MSG(WP_LOG_PK,"outSize= %ld", outsize); // 0
    //WOLFPROV_MSG(WP_LOG_PK,"CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE= %d", CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE); // 16
    //(void)outSize;
    (void)outl;
    (void)out;

    byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    if (ctx->tlsAadLen != UNINITIALISED_SIZET) {
        WOLFPROV_MSG(WP_LOG_PK,"ready for tls cipher, ctx->tlsAadLen != UNINITIALISED_SIZET");
        //ok = wp_aesgcm_tls_cipher(ctx, out, outLen, NULL, 0);
    }
    else {
        ret = wc_ChaCha20Poly1305_Final(&ctx->ChaChaPoly_Aead, (byte*)outAuthTag); // ctx->tag
        if (ret != 0) {
            ok = 0;
        }
        if (ok) {
            ctx->mac_inited = 0;
        }
        //WOLFPROV_MSG(WP_LOG_PK,"done wc_ChaCha20Poly1305_Final ok=%d", ok);

        WOLFPROV_MSG(WP_LOG_PK,"outauthtag: ");
        for (int i = 0; i < CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE; i++) WOLFPROV_MSG(WP_LOG_PK,"%02x", outAuthTag[i]);
        WOLFPROV_MSG(WP_LOG_PK,"");

        // cmp should be done at caller funcs, 
        memcpy(ctx->tag, outAuthTag, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
    }
    *outl = 0; 

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/* ossl_chacha20_ossl_poly1305_functions */
const OSSL_DISPATCH wp_chacha20_poly1305_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))wp_chacha20_poly1305_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))wp_chacha20_poly1305_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))wp_chacha20_poly1305_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))wp_chacha20_poly1305_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))wp_chacha20_poly1305_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))wp_chacha20_poly1305_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))wp_chacha20_poly1305_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))wp_chacha20_poly1305_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS,
        (void (*)(void))wp_chacha20_poly1305_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        (void (*)(void))wp_chacha20_poly1305_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
         (void (*)(void))wp_chacha20_poly1305_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))wp_chacha20_poly1305_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
        (void (*)(void))wp_chacha20_poly1305_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        (void (*)(void))wp_chacha20_poly1305_settable_ctx_params },
    OSSL_DISPATCH_END
};


/* wp_tls_capa.c
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

#include <string.h>
#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/prov_ssl.h>

#include <wolfprovider/wp_logging.h>
#include "wolfprovider/internal.h"


/** Constants associated with TLS groups for parameters. */
typedef struct wp_tls_group_consts {
    unsigned int id;       /** TLS group ID. */
    unsigned int secBits;  /** #Bits of security. */
    int minTls;            /** Minimum TLS version, -1 not supported. */
    int maxTls;            /** Maximum TLS version (or 0 for all). */
    int minDtls;           /** Minimum DTLS version, -1 not supported. */
    int maxDtls;           /** Maximum DTLS version (or 0 for all). */
} wp_tls_group_consts;

#define WP_TLS_12_DOWN      TLS1_VERSION  , TLS1_2_VERSION
#define WP_TLS_10_UP        TLS1_VERSION  , 0
#define WP_TLS_13_UP        TLS1_3_VERSION, 0

#define WP_DTLS_12_DOWN     DTLS1_VERSION  , DTLS1_2_VERSION
#define WP_DTLS_10_UP       DTLS1_VERSION  , 0
#define WP_DTLS_NONE        -1             , -1

/** List of group constants. */
static const wp_tls_group_consts wp_group_const_list[35] = {
    { WOLFSSL_ECC_SECP192R1      ,  80, WP_TLS_12_DOWN, WP_DTLS_12_DOWN },
    { WOLFSSL_ECC_SECP224R1      , 112, WP_TLS_12_DOWN, WP_DTLS_12_DOWN },
    { WOLFSSL_ECC_SECP256R1      , 128, WP_TLS_10_UP  , WP_DTLS_10_UP   },
    { WOLFSSL_ECC_SECP384R1      , 192, WP_TLS_10_UP  , WP_DTLS_10_UP   },
    { WOLFSSL_ECC_SECP521R1      , 256, WP_TLS_10_UP  , WP_DTLS_10_UP   },
    { WOLFSSL_ECC_BRAINPOOLP256R1, 128, WP_TLS_12_DOWN, WP_DTLS_12_DOWN },
    { WOLFSSL_ECC_BRAINPOOLP384R1, 192, WP_TLS_12_DOWN, WP_DTLS_12_DOWN },
    { WOLFSSL_ECC_BRAINPOOLP512R1, 256, WP_TLS_12_DOWN, WP_DTLS_12_DOWN },
    { WOLFSSL_ECC_X25519         , 128, WP_TLS_10_UP  , WP_DTLS_10_UP   },
    { WOLFSSL_ECC_X448           , 224, WP_TLS_10_UP  , WP_DTLS_10_UP   },
    { WOLFSSL_FFDHE_2048         , 112, WP_TLS_13_UP  , WP_DTLS_NONE    },
    { WOLFSSL_FFDHE_3072         , 128, WP_TLS_13_UP  , WP_DTLS_NONE    },
    { WOLFSSL_FFDHE_4096         , 128, WP_TLS_13_UP  , WP_DTLS_NONE    },
    { WOLFSSL_FFDHE_6144         , 128, WP_TLS_13_UP  , WP_DTLS_NONE    },
    { WOLFSSL_FFDHE_8192         , 192, WP_TLS_13_UP  , WP_DTLS_NONE    },
};

/** Parameters for a group. Index references constant list. */
#define WP_TLS_GROUP_ENTRY(tlsName, internalName, idx, alg, algSz)             \
    {                                                                          \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME,                 \
            (char*)tlsName, sizeof(tlsName)),                                  \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,        \
            (char*)internalName, sizeof(internalName)),                        \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG,                  \
            (char*)alg, algSz),                                                \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID,                          \
            (unsigned int *)&wp_group_const_list[idx].id),                     \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,               \
            (unsigned int *)&wp_group_const_list[idx].secBits),                \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,                      \
            (int *)&wp_group_const_list[idx].minTls),                          \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,                      \
            (int *)&wp_group_const_list[idx].maxTls),                          \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,                     \
            (int *)&wp_group_const_list[idx].minDtls),                         \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,                     \
            (int *)&wp_group_const_list[idx].maxDtls),                         \
        OSSL_PARAM_END                                                         \
    }

/** Parameters for an EC group. Index references constant list. */
#define WP_TLS_GROUP_ENTRY_EC(tlsName, internalName, idx)                      \
    WP_TLS_GROUP_ENTRY(tlsName, internalName, idx, "EC", 3)

/** Parameters for an X25519 group. Index references constant list. */
#define WP_TLS_GROUP_ENTRY_X25519(tlsName, internalName, idx)                  \
    WP_TLS_GROUP_ENTRY(tlsName, internalName, idx, "X25519", 7)

/** Parameters for an X448 group. Index references constant list. */
#define WP_TLS_GROUP_ENTRY_X448(tlsName, internalName, idx)                    \
    WP_TLS_GROUP_ENTRY(tlsName, internalName, idx, "X448", 5)

/** Parameters for a DH group. Index references constant list. */
#define WP_TLS_GROUP_ENTRY_DH(tlsName, internalName, idx)                      \
    WP_TLS_GROUP_ENTRY(tlsName, internalName, idx, "DH", 3)

/** List of parameters for TLS groups. */
static const OSSL_PARAM wp_param_group_list[][10] = {
    WP_TLS_GROUP_ENTRY_EC(    "secp192r1"      , "prime192v1"     , 0 ),
    WP_TLS_GROUP_ENTRY_EC(    "P-192"          , "prime192v1"     , 0 ),
    WP_TLS_GROUP_ENTRY_EC(    "secp224r1"      , "secp224r1"      , 1 ),
    WP_TLS_GROUP_ENTRY_EC(    "P-224"          , "secp224r1"      , 1 ),
    WP_TLS_GROUP_ENTRY_EC(    "secp256r1"      , "prime256v1"     , 2 ),
    WP_TLS_GROUP_ENTRY_EC(    "P-256"          , "prime256v1"     , 2 ),
    WP_TLS_GROUP_ENTRY_EC(    "secp384r1"      , "secp384r1"      , 3 ),
    WP_TLS_GROUP_ENTRY_EC(    "P-384"          , "secp384r1"      , 3 ),
    WP_TLS_GROUP_ENTRY_EC(    "secp521r1"      , "secp521r1"      , 4 ),
    WP_TLS_GROUP_ENTRY_EC(    "P-521"          , "secp521r1"      , 4 ),
#ifndef HAVE_FIPS
    WP_TLS_GROUP_ENTRY_EC(    "brainpoolP256r1", "brainpoolP256r1", 5 ),
    WP_TLS_GROUP_ENTRY_EC(    "brainpoolP384r1", "brainpoolP384r1", 6 ),
    WP_TLS_GROUP_ENTRY_EC(    "brainpoolP512r1", "brainpoolP512r1", 7 ),
#endif
    WP_TLS_GROUP_ENTRY_X25519("x25519"         , "X25519"         , 8 ),
    WP_TLS_GROUP_ENTRY_X448(  "x448"           , "X448"           , 9 ),
    WP_TLS_GROUP_ENTRY_DH(    "ffdhe2048"      , "ffdhe2048"      , 10),
    WP_TLS_GROUP_ENTRY_DH(    "ffdhe3072"      , "ffdhe3072"      , 11),
    WP_TLS_GROUP_ENTRY_DH(    "ffdhe4096"      , "ffdhe4096"      , 12),
    WP_TLS_GROUP_ENTRY_DH(    "ffdhe6144"      , "ffdhe6144"      , 13),
    WP_TLS_GROUP_ENTRY_DH(    "ffdhe8192"      , "ffdhe8192"      , 14),
};

/** Count of supported TLS groups. */
#define WP_PARAM_GROUP_CNT  \
    (sizeof(wp_param_group_list) / sizeof(*wp_param_group_list))

/**
 * Pass the list of parameters for TLS groups to the callback.
 *
 * @param [in] cb   Callback.
 * @param [in] arg  Argument for callback.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_tls_group_capability(OSSL_CALLBACK *cb, void *arg)
{
    int ok = 1;
    size_t i;

    for (i = 0; i < WP_PARAM_GROUP_CNT; i++) {
        if (!cb(wp_param_group_list[i], arg)) {
            ok = 0;
            break;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the capabilities of wolfSSL provider.
 *
 * Supports:
 *   TLS-GROUP
 *
 * @param [in] provCtx   Provider context. Unused.
 * @param [in] cb        Callback.
 * @param [in] arg       Argument for callback.
 * @return 1 on success.
 * @return 0 on failure.
 */
int wolfssl_prov_get_capabilities(void *provCtx, const char *capability,
    OSSL_CALLBACK *cb, void *arg)
{
    int ok = 0;

    (void)provCtx;

    if (strcasecmp(capability, "TLS-GROUP") == 0) {
        ok = wp_tls_group_capability(cb, arg);
    }
    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}


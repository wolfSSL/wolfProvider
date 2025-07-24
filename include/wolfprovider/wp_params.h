/* wp_params.h
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

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/types.h>

#ifdef WOLFENGINE_USER_SETTINGS
    #include "user_settings.h"
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/integer.h>

#ifndef WP_PARAMS_H
#define WP_PARAMS_H

/* Used by OSSL_PARAM_free to indicate key type that is data to be freed. */
#define OSSL_PARAM_ALLOCATED_END    127


int wp_mp_read_unsigned_bin_le(mp_int* a, const unsigned char* data,
    size_t len);
int wp_mp_to_unsigned_bin_le(mp_int* mp, unsigned char* data, size_t len);

void wp_param_set_utf8_string_ptr(OSSL_PARAM* p, const char* key,
    const char* str);
void wp_param_set_octet_string_ptr(OSSL_PARAM* p, const char* key,
    const unsigned char* data, size_t len);
void wp_param_set_int(OSSL_PARAM* p, const char* key, int* val);
int wp_param_set_mp(OSSL_PARAM* p, const char* key, mp_int* mp,
    unsigned char* data, size_t* idx);
void wp_param_set_mp_buf(OSSL_PARAM* p, const char* key, unsigned char* num,
    size_t nLen, unsigned char* data, size_t* idx);

int wp_params_get_digest(const OSSL_PARAM* params, char* name,
    OSSL_LIB_CTX* libCtx, enum wc_HashType* type, size_t* len);
int wp_params_get_mp(const OSSL_PARAM* params, const char* key, mp_int* mp,
    int *set);
int wp_params_get_octet_string(const OSSL_PARAM* params, const char* key,
    unsigned char** data, size_t* len, int secure);
int wp_params_get_bn_be(const OSSL_PARAM* params, const char* key,
    unsigned char** data, size_t* len, int secure);
int wp_params_get_utf8_string(const OSSL_PARAM* params, const char* key,
    char* str, size_t len);
int wp_params_get_octet_string_ptr(const OSSL_PARAM* params, const char* key,
    unsigned char** data, size_t* len);
int wp_params_get_utf8_string_ptr(const OSSL_PARAM* params, const char* key,
    const char** data);
int wp_params_get_size_t(const OSSL_PARAM* params, const char* key,
    size_t* val);
int wp_params_get_uint64(const OSSL_PARAM* params, const char* key,
    uint64_t* val);
int wp_params_get_int(const OSSL_PARAM* params, const char* key, int* val);
int wp_params_get_uint(const OSSL_PARAM* params, const char* key,
    unsigned int* val, int* set);

int wp_params_set_mp(OSSL_PARAM params[], const char* key, mp_int* mp,
    int allow);
int wp_params_set_octet_string_be(OSSL_PARAM params[], const char* key,
    unsigned char* data, size_t len);
int wp_params_count(const OSSL_PARAM *p);
#endif /* WP_PARAMS_H */


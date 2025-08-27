/* wp_params.c
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


#include <openssl/evp.h>

#include "wolfprovider/internal.h"
#include "wolfprovider/wp_params.h"
#include "wolfprovider/wp_logging.h"


/**
 * Read little-endian array of bytes representing a large number.
 *
 * @param [in, out] mp    Multi-precision number.
 * @param [in]      data  Little-endian array of bytes.
 * @param [in]      len   Length of array in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_mp_read_unsigned_bin_le(mp_int* mp, const unsigned char* data,
    size_t len)
{
    int ok = 1;
    unsigned char rdata[1024];
    size_t i;
    int rc;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_mp_read_unsigned_bin_le");

    /* Make big-endian. */
    for (i = 0; i < len; i++) {
        rdata[i] = data[len - 1 - i];
    }

    /* Read big-endian data in. */
    rc = mp_read_unsigned_bin(mp, rdata, (word32)len);
    if (rc != 0) {
        WOLFPROV_MSG(WP_LOG_PROVIDER, "mp_read_unsigned_bin failed with rc=%d", rc);
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Convert an wolfSSL mp_int to a local endian byte array encoding.
 *
 * @param [in]      mp    Multi-precision number.
 * @param [in, out] data  Buffer to hold encoded number.
 * @param [in]      len   Length of buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_mp_to_unsigned_bin_le(mp_int* mp, unsigned char* data, size_t len)
{
    int ok = 1;
    int rc;
    size_t i;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_mp_to_unsigned_bin_le");

    rc = mp_to_unsigned_bin(mp, data);
    if (rc != 0) {
        WOLFPROV_MSG(WP_LOG_PROVIDER, "mp_to_unsigned_bin failed with rc=%d", rc);
        ok = 0;
    }
#ifdef LITTLE_ENDIAN_ORDER
    if (ok) {
        for (i = 0; i < len / 2; i++) {
            unsigned char t = data[i];
            data[i] = data[len - 1 - i];
            data[len - 1 - i] = t;
        }
    }
#endif

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set a parameter to a UTF8 string.
 *
 * @param [in, out] p    Parameter element.
 * @param [in]      key  Key for parameter.
 * @param [in]      str  UTF8 string to set.
 */
void wp_param_set_utf8_string_ptr(OSSL_PARAM* p, const char* key,
    const char* str)
{
    p->key = key;
    p->data_type = OSSL_PARAM_UTF8_STRING;
    p->return_size = p->data_size = XSTRLEN(str);
    p->data = (void*)str;
}
/**
 * Set a parameter to an OCTET string.
 *
 * @param [in, out] p     Parameter element.
 * @param [in]      key   Key for parameter.
 * @param [in]      data  OCTET string to set.
 * @param [in]      len   Length of OCTET string in bytes.
 */
void wp_param_set_octet_string_ptr(OSSL_PARAM* p, const char* key,
    const unsigned char* data, size_t len)
{
    p->key = key;
    p->data_type = OSSL_PARAM_OCTET_STRING;
    p->return_size = p->data_size = len;
    p->data = (void*)data;
}
/**
 * Set a parameter to an integer.
 *
 * @param [in, out] p    Parameter element.
 * @param [in]      key  Key for parameter.
 * @param [in]      val  Pointer to the integer.
 */
void wp_param_set_int(OSSL_PARAM* p, const char* key,
    int* val)
{
    p->key = key;
    p->data_type = OSSL_PARAM_INTEGER;
    p->return_size = p->data_size = sizeof(int);
    p->data = (void*)val;
}
/**
 * Set a multi-precision number into parameters as an unsigned integer encoding.
 *
 * Assumes the data array is big enough for encoding.
 *
 * @param [in, out] p     Parameter element.
 * @param [in]      key   Key for parameter.
 * @param [in]      mp    Multi-precision integer.
 * @param [in]      data  Array to encode into.
 * @param [in, out] idx   On in, index into array to start encoding.
 *                        On out, index after data placed.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_param_set_mp(OSSL_PARAM* p, const char* key, mp_int* mp,
    unsigned char* data, size_t* idx)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_param_set_mp");

    p->key = key;
    p->data_type = OSSL_PARAM_UNSIGNED_INTEGER;
    p->return_size = p->data_size = mp_unsigned_bin_size(mp);
    p->data = data + *idx;
    *idx += p->data_size;
    if (!wp_mp_to_unsigned_bin_le(mp, p->data, p->data_size)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
/**
 * Set a multi-precision buffer into parameters as an unsigned integer encoding.
 *
 * @param [in, out] p     Parameter element.
 * @param [in]      key   Key for parameter.
 * @param [in]      num   Multi-precision buffer.
 * @param [in]      nLen  Length of multi-precision number data in bytes.
 * @param [in]      data  Array to encode into.
 * @param [in, out] idx   On in, index into array to start encoding.
 *                        On out, index after data placed.
 */
void wp_param_set_mp_buf(OSSL_PARAM* p, const char* key, unsigned char* num,
    size_t nLen, unsigned char* data, size_t* idx)
{
    size_t i;

    p->key = key;
    p->data_type = OSSL_PARAM_UNSIGNED_INTEGER;
    p->data_size = nLen;
    p->data = data + *idx;
    *idx += p->data_size;
    data = p->data;
#ifdef LITTLE_ENDIAN_ORDER
    for (i = 0; i < nLen; i++) {
        data[i] = num[nLen - 1 - i];
    }
#endif
}

/**
 * Get a digest name from the parameters.
 *
 * Returns success if parameter not found.
 * Copies the name and returns the wolfSSL hash type and length of output.
 *
 * @param [in]  params  Array of parameters.
 * @param [out] name    Buffer to hold hash name.
 * @param [in]  libCtx  Library context to lookup name in.
 * @param [out] type    wolfCrypt hash type corresponding to name. May be NULL.
 * @param [out] len     Length of digest output in bytes. May be NULL.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_params_get_digest(const OSSL_PARAM* params, char* name,
    OSSL_LIB_CTX* libCtx, enum wc_HashType* type, size_t* len)
{
    int ok = 1;
    const char* mdName = NULL;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_params_get_digest");

    if (!wp_params_get_utf8_string_ptr(params, OSSL_ALG_PARAM_DIGEST,
            &mdName)) {
        ok = 0;
    }
    if (ok && (mdName != NULL)) {
        const char* mdProps = NULL;

        if (name != NULL) {
            XMEMCPY(name, mdName, XSTRLEN(mdName) + 1);
        }
        if (ok && (type != NULL) && (!wp_params_get_utf8_string_ptr(params,
                    OSSL_ALG_PARAM_PROPERTIES, &mdProps))) {
            ok = 0;
        }
        if (ok && (type != NULL)) {
            *type = wp_name_to_wc_hash_type(libCtx, mdName, mdProps);
            if (*type == WC_HASH_TYPE_NONE) {
                ok = 0;
            }
            if (ok && (len != NULL)) {
                *len = wc_HashGetDigestSize(*type);
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get a multi-precision number from the parameters.
 *
 * Returns success if parameter not found.
 *
 * @param [in]  params  Array of parameters.
 * @param [in]  key     String key to look for.
 * @param [out] mp      Multi-precision number.
 * @param [out] set     Indicates if mp has been set.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_params_get_mp(const OSSL_PARAM* params, const char* key, mp_int* mp,
                     int *set)
{
    int ok = 1;
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_params_get_mp");

    if (set != NULL) {
        *set = 0;
    }

    p = OSSL_PARAM_locate_const(params, key);
    if ((p != NULL) && (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)) {
        ok = 0;
    }
    if (ok && (p != NULL)) {
        if (!wp_mp_read_unsigned_bin_le(mp, p->data, p->data_size)) {
            ok = 0;
        }
        else {
            if (set != NULL) {
                *set = 1;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get an octet string from the parameters.
 *
 * Returns success if parameter not found.
 *
 * @param [in]      params  Array of parameters.
 * @param [in]      key     String key to look for.
 * @param [in, out] data    Byte array that may have been previously allocated..
 * @param [out]     len     Length of data in byte array.
 * @param [in]      secure  Data is sensitive and needs to be secured.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_params_get_octet_string(const OSSL_PARAM* params, const char* key,
    unsigned char** data, size_t* len, int secure)
{
    int ok = 1;
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_params_get_octet_string");

    p = OSSL_PARAM_locate_const(params, key);
    if (p != NULL) {
        if (secure) {
            OPENSSL_clear_free(*data, *len);
        }
        else {
            OPENSSL_free(*data);
        }
        *data = NULL;
        if (!OSSL_PARAM_get_octet_string(p, (void**)data, 0, len)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get Big Number as a big-endian byte array.
 *
 * Returns success if parameter not found.
 *
 * @param [in]      params  Array of parameters.
 * @param [in]      key     String key to look for.
 * @param [in, out] data    Byte array that may have been previously allocated.
 * @param [out]     len     Length of data in byte array.
 * @param [in]      secure  Data is sensitive and needs to be secured.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_params_get_bn_be(const OSSL_PARAM* params, const char* key,
    unsigned char** data, size_t* len, int secure)
{
    int ok = 1;
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_params_get_bn_be");

    p = OSSL_PARAM_locate_const(params, key);
    if ((p != NULL) && (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)) {
            ok = 0;
    }
    if ((p != NULL) && ok) {
        if (secure) {
            OPENSSL_clear_free(*data, *len);
        }
        else {
            OPENSSL_free(*data);
        }
        *data = OPENSSL_malloc(p->data_size);
        if (*data == NULL) {
            ok = 0;
        }
    }
    if ((p != NULL) && ok) {
#ifdef LITTLE_ENDIAN_ORDER
        size_t i;
        unsigned char* a = *data;
        unsigned char* b = (unsigned char*)p->data;
        size_t l = *len = p->data_size;

        for (i = 0; i < l; i++) {
            a[i] = b[l - 1 - i];
        }
#else
        XMEMCPY(*data, p->data, p->data_size);
#endif
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get an OCTET string. The pointer from the parameter is returned.
 *
 * Returns success if parameter not found.
 *
 * @param [in]  params  Array of parameters.
 * @param [in]  key     String key to look for.
 * @param [out] data    Byte array with octet string.
 * @param [out] len     Length of data in byte array.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_params_get_octet_string_ptr(const OSSL_PARAM* params, const char* key,
    unsigned char** data, size_t* len)
{
    int ok = 1;
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_params_get_octet_string_ptr");

    p = OSSL_PARAM_locate_const(params, key);
    if ((p != NULL) && (p->data_type != OSSL_PARAM_OCTET_STRING)) {
        ok = 0;
    }
    if ((p != NULL) && ok) {
        *data = (unsigned char *)p->data;
        *len  = p->data_size;
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get a UTF8 string from the parameters.
 *
 * Returns success if parameter not found.
 *
 * @param [in]  params  Array of parameters.
 * @param [in]  key     String key to look for.
 * @param [out] str     String to copy into.
 * @param [in]  len     Length of string buffer.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_params_get_utf8_string(const OSSL_PARAM* params, const char* key,
    char* str, size_t len)
{
    int ok = 1;
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_params_get_utf8_string");

    p = OSSL_PARAM_locate_const(params, key);
    if ((p != NULL) && (p->data_type != OSSL_PARAM_UTF8_STRING)) {
        ok = 0;
    }
    if ((p != NULL) && ok && (p->data_size > len)) {
        ok = 0;
    }
    if ((p != NULL) && ok) {
        XSTRNCPY(str, p->data, len);
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get a UTF8 string. The pointer from the parameter is returned.
 *
 * Returns success if parameter not found.
 *
 * @param [in]  params  Array of parameters.
 * @param [in]  key     String key to look for.
 * @param [out] data    String with octet string.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_params_get_utf8_string_ptr(const OSSL_PARAM* params, const char* key,
    const char** data)
{
    int ok = 1;
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_params_get_utf8_string_ptr");

    p = OSSL_PARAM_locate_const(params, key);
    if ((p != NULL) && (p->data_type != OSSL_PARAM_UTF8_STRING)) {
        ok = 0;
    }
    if ((p != NULL) && ok) {
        *data = (char *)p->data;
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get a value of type size_t.
 *
 * Returns success if parameter not found.
 *
 * @param [in]  params  Array of parameters.
 * @param [in]  key     String key to look for.
 * @param [out] val     Value from parameter.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_params_get_size_t(const OSSL_PARAM* params, const char* key, size_t* val)
{
    int ok = 1;
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_params_get_size_t");

    p = OSSL_PARAM_locate_const(params, key);
    if ((p != NULL) && (!OSSL_PARAM_get_size_t(p, val))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get a value of type uint64_t.
 *
 * Returns success if parameter not found.
 *
 * @param [in]  params  Array of parameters.
 * @param [in]  key     String key to look for.
 * @param [out] val     Value from parameter.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_params_get_uint64(const OSSL_PARAM* params, const char* key,
    uint64_t* val)
{
    int ok = 1;
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_params_get_uint64");

    p = OSSL_PARAM_locate_const(params, key);
    if ((p != NULL) && (!OSSL_PARAM_get_uint64(p, val))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get a value of type int.
 *
 * Returns success if parameter not found.
 *
 * @param [in]  params  Array of parameters.
 * @param [in]  key     String key to look for.
 * @param [out] val     Value from parameter.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_params_get_int(const OSSL_PARAM* params, const char* key, int* val)
{
    int ok = 1;
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_params_get_int");

    p = OSSL_PARAM_locate_const(params, key);
    if ((p != NULL) && (!OSSL_PARAM_get_int(p, val))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get a value of type unsigned int.
 *
 * Returns success if parameter not found.
 *
 * @param [in]  params  Array of parameters.
 * @param [in]  key     String key to look for.
 * @param [out] val     Value from parameter.
 * @param [out] set     Indicates whether the parameter was found and value set.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_params_get_uint(const OSSL_PARAM* params, const char* key,
    unsigned int* val, int* set)
{
    int ok = 1;
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_params_get_uint");

    if (set != NULL) {
        *set = 0;
    }
    p = OSSL_PARAM_locate_const(params, key);
    if ((p != NULL) && (!OSSL_PARAM_get_uint(p, val))) {
        ok = 0;
    }
    if (ok && (p != NULL) && (set != NULL)) {
        *set = 1;
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}


/**
 * Set a multi-precision number into the parameters.
 *
 * Returns success if parameter not found.
 *
 * @param [in, out] params  Array of parameters.
 * @param [in]      key     String key to look for.
 * @param [in]      mp      Multi-precision number.
 * @param [in]      allow   This mp is allowed to be set.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_params_set_mp(OSSL_PARAM params[], const char* key, mp_int* mp,
                     int allow)
{
    int ok = 1;
    OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_params_set_mp");

    p = OSSL_PARAM_locate(params, key);
    if ((p != NULL) && (allow != 1)) {
        ok = 0;
    }
    if (ok && (p != NULL)) {
        size_t outLen = mp_unsigned_bin_size(mp);
        if (p->data != NULL) {
            if (p->data_size < outLen) {
                ok = 0;
            }
            if (ok && !wp_mp_to_unsigned_bin_le(mp, p->data, outLen)) {
                ok = 0;
            }
        }
        p->return_size = outLen;
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set a number as a big-endian byte array as an unsigned integer.
 *
 * Returns success if parameter not found.
 *
 * @param [in, out] params  Array of parameters.
 * @param [in]      key     String key to look for.
 * @param [in]      data    Big-endian byte array representing a number.
 * @param [in]      len     Length of byte array.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_params_set_octet_string_be(OSSL_PARAM params[], const char* key,
    unsigned char* data, size_t len)
{
    int ok = 1;
    OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_PROVIDER, "wp_params_set_octet_string_be");

    p = OSSL_PARAM_locate(params, key);
    if (p != NULL) {
        if ((p->data == NULL) || (p->data_size < len)) {
            ok = 0;
        }
    }
    if ((p != NULL) && ok) {
#ifdef LITTLE_ENDIAN_ORDER
        size_t i;
        unsigned char* pData = (unsigned char*)p->data;

        for (i = 0; i < len; i++) {
            pData[i] = data[len - 1 - i];
        }
#else
        XMEMCPY(p->data, data, len);
#endif
    }
    if ((p != NULL) && ok) {
        p->return_size = len;
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Count the number of parameters in the array, not including the end marker.
 *
 * @param [in]      params  Array of parameters.
 * @return  number of parameters in the array.
 */
int wp_params_count(const OSSL_PARAM *p)
{
    int cnt = 0;
    while ((p != NULL) && (p->key != NULL)) {
         cnt++;
         p++;
     }
     return cnt;
}

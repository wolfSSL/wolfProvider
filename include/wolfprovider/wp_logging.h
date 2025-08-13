/* wp_logging.h
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

#ifndef WP_LOGGING_H
#define WP_LOGGING_H

#ifdef WOLFPROV_USER_SETTINGS
    #include "user_settings.h"
#endif


#if defined(__IAR_SYSTEMS_ICC__) || defined(__GNUC__)
    /* Function is a printf style function. Pretend parameter is string literal.
     *
     * @param s  [in]  Index of string literal. Index from 1.
     * @param v  [in]  Index of first argument to check. 0 means don't.
     */
    #define WP_PRINTF_FUNC(s, v)  __attribute__((__format__ (__printf__, s, v)))
#else
    #define WP_PRINTF_FUNC(s, v)
#endif


#ifndef WOLFPROV_MAX_LOG_WIDTH
#define WOLFPROV_MAX_LOG_WIDTH 120
#endif

/* wolfProv debug logging support can be compiled in by defining
 * WOLFPROV_DEBUG or by using the --enable-debug configure option.
 *
 * wolfProv supports the log levels as mentioned in wolfProv_LogType
 * enum below. The default logging level when debug logging is compiled in
 * and enabled at runtime is WP_LOG_LEVEL_DEFAULT.
 *
 * wolfProv supports log message control per-component/algorithm type,
 * with all possible logging components in wolfProv_LogComponents enum
 * below. The default logging level when debug logging is compiled in and
 * enabled at runtime is WP_LOG_COMPONENTS_DEFAULT.
 *
 */

/* Possible debug/logging options:
 *
 * WOLFPROV_DEBUG       Define to enable debug logging (or --enable-debug)
 * WOLFPROV_USER_LOG    Defines name of function for log output. By default
 *                        wolfProv will log with fprintf to stderr. Users
 *                        can define this to a custom log function to be used
 *                        in place of fprintf. Alternatively, users can
 *                        register a logging callback for custom logging.
 * WOLFPROV_LOG_PRINTF  Define to Use printf instead of fprintf (to stderr)
 *                        for logs. Not applicable if using WOLFPROV_USER_LOG
 *                        or custom logging callback.
 *
 * COMPILE-TIME MACRO CONFIGURATIONS:
 * Define these macros in this header to control logging at compile time:
 * NOTE: wolfProvider needs to be built with --debug to enable the logging first
 * before we can set the log level and components.
 * 
 * WOLFPROV_LOG_LEVEL_FILTER Sets the log level. Use WP_LOG_* constants from enum below.
 *                        Examples:
 *                        - WP_LOG_ERROR (only errors)
 *                        - (WP_LOG_ERROR | WP_LOG_ENTER) (errors and function enter)
 *                        - (WP_LOG_ERROR | WP_LOG_LEAVE) (errors and function leave)
 *                        - (WP_LOG_LEVEL_ALL) (all levels)
 *
 * WOLFPROV_LOG_COMPONENTS_FILTER  Set component bitmask to filter specific
 *                        algorithms. Use WP_LOG_* constants from enum below.
 *                        Examples:
 *                        - WP_LOG_HKDF (HKDF only)
 *                        - (WP_LOG_AES | WP_LOG_DES) (ciphers only)
 *                        - (WP_LOG_ECC | WP_LOG_RSA | WP_LOG_HKDF) (multiple algorithms)
 *                        - WP_LOG_CIPHER (all cipher operations)
 *
 * EXAMPLES:
 * #define WOLFPROV_LOG_LEVEL_FILTER (WP_LOG_ERROR | WP_LOG_ENTER | WP_LOG_LEAVE | WP_LOG_INFO)
 * #define WOLFPROV_LOG_COMPONENTS_FILTER WP_LOG_HKDF
 * // Shows level (ERROR + ENTER/LEAVE + INFO) for HKDF operations only
 *
 * #define WOLFPROV_LOG_LEVEL_FILTER (WP_LOG_LEVEL_ALL)
 * #define WOLFPROV_LOG_COMPONENTS_FILTER (WP_LOG_ECC | WP_LOG_RSA | WP_LOG_HKDF)
 * // Shows level (ERROR + ENTER/LEAVE + INFO + VERBOSE + DEBUG + TRACE) for ECC, RSA, and HKDF only
 */
enum wolfProv_LogType {
    WP_LOG_ERROR   = 0x0001,   /* logs errors */
    WP_LOG_ENTER   = 0x0002,   /* logs function enter*/
    WP_LOG_LEAVE   = 0x0004,   /* logs function leave */
    WP_LOG_INFO    = 0x0008,   /* logs informative messages */
    WP_LOG_VERBOSE = 0x0010,   /* logs encrypted/decrypted/digested data */
    WP_LOG_DEBUG   = 0x0020,   /* logs debug-level detailed information */
    WP_LOG_TRACE   = 0x0040,   /* logs trace-level ultra-detailed information */

    /* default log level when logging is turned on */
    WP_LOG_LEVEL_DEFAULT = (WP_LOG_ERROR | WP_LOG_LEAVE | WP_LOG_INFO),

    /* log all, including verbose */
    WP_LOG_LEVEL_ALL = (WP_LOG_ERROR
                      | WP_LOG_ENTER
                      | WP_LOG_LEAVE
                      | WP_LOG_INFO
                      | WP_LOG_VERBOSE
                      | WP_LOG_DEBUG
                      | WP_LOG_TRACE)
};

enum wolfProv_LogComponents {
    /* Legacy component categories */
    WP_LOG_RNG      = 0x0001,   /* random number generation */
    WP_LOG_DIGEST   = 0x0002,   /* digest (SHA-1/2/3) */
    WP_LOG_MAC      = 0x0004,   /* mac functions: HMAC, CMAC */
    WP_LOG_CIPHER   = 0x0008,   /* cipher (AES, 3DES) */
    WP_LOG_PK       = 0x0010,   /* public key algorithms (RSA, ECC) */
    WP_LOG_KE       = 0x0020,   /* key agreement (DH, ECDH) */
    WP_LOG_KDF      = 0x0040,   /* password base key derivation algorithms */
    WP_LOG_PROVIDER = 0x0080,   /* all provider specific logs */
    
    /* Granular algorithm family categories */
    WP_LOG_RSA      = 0x0001,   /* RSA operations */
    WP_LOG_ECC      = 0x0002,   /* ECC operations */
    WP_LOG_DH       = 0x0004,   /* Diffie-Hellman operations */
    WP_LOG_AES      = 0x0008,   /* AES cipher operations */
    WP_LOG_DES      = 0x0010,   /* 3DES cipher operations */
    WP_LOG_SHA      = 0x0020,   /* SHA digest operations */
    WP_LOG_MD5      = 0x0040,   /* MD5 digest operations */
    WP_LOG_HMAC     = 0x0080,   /* HMAC operations */
    WP_LOG_CMAC     = 0x0100,   /* CMAC operations */
    WP_LOG_HKDF     = 0x0200,   /* HKDF operations */
    WP_LOG_PBKDF2   = 0x0400,   /* PBKDF2 operations */
    WP_LOG_KRB5KDF  = 0x0800,   /* KRB5KDF operations */
    WP_LOG_DRBG     = 0x1000,   /* DRBG operations */
    WP_LOG_ECDSA    = 0x2000,   /* ECDSA signature operations */
    WP_LOG_ECDH     = 0x4000,   /* ECDH key exchange operations */
    WP_LOG_ED25519  = 0x8000,   /* Ed25519 operations */
    WP_LOG_ED448    = 0x10000,  /* Ed448 operations */
    WP_LOG_X25519   = 0x20000,  /* X25519 operations */
    WP_LOG_X448     = 0x40000,  /* X448 operations */
    WP_LOG_QUERY    = 0x80000,  /* wolfprov_query operations */
    WP_LOG_TLS1_PRF = 0x100000, /* TLS1 PRF operations */

    /* log all compoenents */
    WP_LOG_COMPONENTS_ALL = (WP_LOG_RNG
                           | WP_LOG_DIGEST
                           | WP_LOG_MAC
                           | WP_LOG_CIPHER
                           | WP_LOG_PK
                           | WP_LOG_KE
                           | WP_LOG_KDF
                           | WP_LOG_PROVIDER
                           | WP_LOG_RSA
                           | WP_LOG_ECC
                           | WP_LOG_DH
                           | WP_LOG_AES
                           | WP_LOG_DES
                           | WP_LOG_SHA
                           | WP_LOG_MD5
                           | WP_LOG_HMAC
                           | WP_LOG_CMAC
                           | WP_LOG_HKDF
                           | WP_LOG_PBKDF2
                           | WP_LOG_KRB5KDF
                           | WP_LOG_DRBG
                           | WP_LOG_ECDSA
                           | WP_LOG_ECDH
                           | WP_LOG_ED25519
                           | WP_LOG_ED448
                           | WP_LOG_X25519
                           | WP_LOG_X448
                           | WP_LOG_QUERY
                           | WP_LOG_TLS1_PRF),

    /* default compoenents logged */
    WP_LOG_COMPONENTS_DEFAULT = WP_LOG_COMPONENTS_ALL
};

/* Manually set the log level */
#ifndef WOLFPROV_LOG_LEVEL_FILTER
#define WOLFPROV_LOG_LEVEL_FILTER WP_LOG_LEVEL_DEFAULT
#endif

/* Manually set the components */
#ifndef WOLFPROV_LOG_COMPONENTS_FILTER
#define WOLFPROV_LOG_COMPONENTS_FILTER WP_LOG_COMPONENTS_DEFAULT
#endif

/* Conditional logging macro that checks compile-time configuration */
#ifdef WOLFPROV_DEBUG
    #define WOLFPROV_COMPILE_TIME_CHECK(component, level) \
        ((WOLFPROV_LOG_LEVEL_FILTER & (level)) && \
         (WOLFPROV_LOG_COMPONENTS_FILTER & (component)))
#else
    #define WOLFPROV_COMPILE_TIME_CHECK(component, level) 0
#endif

typedef void (*wolfProv_Logging_cb)(const int logLevel, const int component,
    const char *const logMessage);
int wolfProv_SetLoggingCb(wolfProv_Logging_cb logF);

/* turn logging on, only if compiled in */
int  wolfProv_Debugging_ON(void);
/* turn logging off */
void wolfProv_Debugging_OFF(void);

/* Set logging level, bitmask of wolfProv_LogType */
int wolfProv_SetLogLevel(int levelMask);
/* Set which components are logged, bitmask of wolfProv_LogComponents */
int wolfProv_SetLogComponents(int componentMask);

#ifdef WOLFPROV_DEBUG

#define WOLFPROV_STRINGIZE_HELPER(x) #x
#define WOLFPROV_STRINGIZE(x) WOLFPROV_STRINGIZE_HELPER(x)

#define WOLFPROV_ERROR(type, err)                                           \
    WOLFPROV_ERROR_LINE(type, err, __FILE__, __LINE__)
#define WOLFPROV_ERROR_MSG(type, msg)                                       \
    WOLFPROV_ERROR_MSG_LINE(type, msg, __FILE__, __LINE__)
#define WOLFPROV_ERROR_FUNC(type, funcName, ret)                            \
    WOLFPROV_ERROR_FUNC_LINE(type, funcName, ret, __FILE__, __LINE__)
#define WOLFPROV_ERROR_FUNC_NULL(type, funcName, ret)                       \
    WOLFPROV_ERROR_FUNC_NULL_LINE(type, funcName, ret, __FILE__, __LINE__)

void WOLFPROV_ENTER(int type, const char* msg);
/* Call the extended version of the API with the function name of the caller. */
#ifdef _WIN32
    #define WOLFPROV_LEAVE(type, msg, ret) \
        WOLFPROV_LEAVE_EX(type, __FUNCTION__, msg, ret)
#elif __STDC__ && __STDC_VERSION__ >= 199901L
    #define WOLFPROV_LEAVE(type, msg, ret) \
        WOLFPROV_LEAVE_EX(type, __func__, msg, ret)
#else
    #define WOLFPROV_LEAVE(type, msg, ret) \
        WOLFPROV_LEAVE_EX(type, "", msg, ret)
#endif
void WOLFPROV_LEAVE_EX(int type, const char* func, const char* msg, int ret);
void WOLFPROV_MSG(int type, const char* fmt, ...);
void WOLFPROV_MSG_VERBOSE(int type, const char* fmt, ...);
void WOLFPROV_MSG_DEBUG(int type, const char* fmt, ...);
void WOLFPROV_MSG_TRACE(int type, const char* fmt, ...);
void WOLFPROV_ERROR_LINE(int type, int err, const char* file, int line);
void WOLFPROV_ERROR_MSG_LINE(int type, const char* msg, const char* file,
    int line);
void WOLFPROV_ERROR_FUNC_LINE(int type, const char* funcName, int ret,
    const char* file, int line);
void WOLFPROV_ERROR_FUNC_NULL_LINE(int type, const char* funcName,
    const void *ret, const char* file, int line);
void WOLFPROV_BUFFER(int type, const unsigned char* buffer,
    unsigned int length);

#else /* WOLFPROV_DEBUG */

#define WOLFPROV_ENTER(t, m)
#define WOLFPROV_LEAVE(t, m, r)
#define WOLFPROV_MSG(t, m, ...)
#define WOLFPROV_MSG_VERBOSE(t, m, ...)
#define WOLFPROV_MSG_DEBUG(t, m, ...)
#define WOLFPROV_MSG_TRACE(t, m, ...)
#define WOLFPROV_ERROR(t, e)
#define WOLFPROV_ERROR_MSG(t, e)
#define WOLFPROV_ERROR_FUNC(t, f, r)
#define WOLFPROV_ERROR_FUNC_NULL(t, f, r)
#define WOLFPROV_BUFFER(t, b, l)

#endif /* WOLFPROV_DEBUG */

#endif /* WP_LOGGING_H */


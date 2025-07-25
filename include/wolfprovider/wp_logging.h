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
 */
enum wolfProv_LogType {
    WP_LOG_ERROR   = 0x0001,  /* logs errors */
    WP_LOG_ENTER   = 0x0002,  /* logs function enter*/
    WP_LOG_LEAVE   = 0x0004,  /* logs function leave */
    WP_LOG_INFO    = 0x0008,  /* logs informative messages */
    WP_LOG_VERBOSE = 0x0010,  /* logs encrypted/decrypted/digested data */

    /* default log level when logging is turned on, all but verbose */
    WP_LOG_LEVEL_DEFAULT = (WP_LOG_ERROR
                          | WP_LOG_ENTER
                          | WP_LOG_LEAVE
                          | WP_LOG_INFO),

    /* log all, including verbose */
    WP_LOG_LEVEL_ALL = (WP_LOG_ERROR
                      | WP_LOG_ENTER
                      | WP_LOG_LEAVE
                      | WP_LOG_INFO
                      | WP_LOG_VERBOSE)
};

enum wolfProv_LogComponents {
    WP_LOG_RNG      = 0x0001,  /* random number generation */
    WP_LOG_DIGEST   = 0x0002,  /* digest (SHA-1/2/3) */
    WP_LOG_MAC      = 0x0004,  /* mac functions: HMAC, CMAC */
    WP_LOG_CIPHER   = 0x0008,  /* cipher (AES, 3DES) */
    WP_LOG_PK       = 0x0010,  /* public key algorithms (RSA, ECC) */
    WP_LOG_KE       = 0x0020,  /* key agreement (DH, ECDH) */
    WP_LOG_KDF      = 0x0040,  /* password base key derivation algorithms */
    WP_LOG_PROVIDER = 0x0080,  /* all provider specific logs */

    /* log all compoenents */
    WP_LOG_COMPONENTS_ALL = (WP_LOG_RNG
                           | WP_LOG_DIGEST
                           | WP_LOG_MAC
                           | WP_LOG_CIPHER
                           | WP_LOG_PK
                           | WP_LOG_KE
                           | WP_LOG_KDF
                           | WP_LOG_PROVIDER),

    /* default compoenents logged */
    WP_LOG_COMPONENTS_DEFAULT = WP_LOG_COMPONENTS_ALL
};

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
void WOLFPROV_ERROR_LINE(int type, int err, const char* file, int line);
void WOLFPROV_ERROR_MSG_LINE(int type, const char* msg, const char* file,
    int line);
void WOLFPROV_ERROR_FUNC_LINE(int type, const char* funcName, int ret,
    const char* file, int line);
void WOLFPROV_ERROR_FUNC_NULL_LINE(int type, const char* funcName,
    const void *ret, const char* file, int line);
void WOLFPROV_BUFFER(int type, const unsigned char* buffer,
    unsigned int length);

#else

#define WOLFPROV_ENTER(t, m)
#define WOLFPROV_LEAVE(t, m, r)
#define WOLFPROV_MSG(t, m, ...)
#define WOLFPROV_MSG_VERBOSE(t, m, ...)
#define WOLFPROV_ERROR(t, e)
#define WOLFPROV_ERROR_MSG(t, e)
#define WOLFPROV_ERROR_FUNC(t, f, r)
#define WOLFPROV_ERROR_FUNC_NULL(t, f, r)
#define WOLFPROV_BUFFER(t, b, l)

#endif /* WOLFPROV_DEBUG */

#endif /* WP_LOGGING_H */


/* wp_logging.c
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

#include <wolfprovider/internal.h>
#include <wolfprovider/wp_logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFPROV_DEBUG

#ifdef WOLFPROV_USER_LOG
    /* user includes their own headers */
#else
    #include <stdio.h>  /* for default printf/fprintf */
#endif

/* Used for variable arguments in WOLFPROV_MSG and WOLFPROV_MSG_VERBOSE */
#include <stdarg.h>

/* Application callback function, set with wolfProv_SetLoggingCb() */
static wolfProv_Logging_cb log_function = NULL;

/* Flag indicating if logging is enabled, controlled via
 * wolfProv_Debugging_ON() and wolfProv_Debugging_OFF() */
static int loggingEnabled = 1;

/* Logging level. Bitmask of logging levels in wolfProv_LogType.
 * Default log level includes error, enter/leave, and info. Does not turn on
 * verbose by default. */
static int providerLogLevel = WP_LOG_LEVEL_ALL;

/* Components which will be logged when debug enabled. Bitmask of components
 * in wolfProv_LogComponents. Default components include all. */
static int providerLogComponents = WP_LOG_COMPONENTS_ALL;

#endif /* WOLFPROV_DEBUG */


/**
 * Registers wolfProv logging callback.
 * Callback will be used by wolfProv for debug/log messages.
 *
 * @param f Callback function, prototyped by wolfProv_Logging_cb. Callback
 *          function may be NULL to reset logging redirection back to default
 *          output.
 * @return 0 on success, NOT_COMPILED_IN if debugging has
 *         not been enabled.
 */
int wolfProv_SetLoggingCb(wolfProv_Logging_cb f)
{
#ifdef WOLFPROV_DEBUG
    log_function = f;
    return 0;
#else
    (void)f;
    return NOT_COMPILED_IN;
#endif
}

/**
 * Enable debug logging.
 *
 * @return 0 on success, NOT_COMPILED_IN if debugging has
 *         not been enabled.
 */
int wolfProv_Debugging_ON(void)
{
#ifdef WOLFPROV_DEBUG
    loggingEnabled = 1;
    return 0;
#else
    return NOT_COMPILED_IN;
#endif
}

/**
 * Disable debug logging.
 */
void wolfProv_Debugging_OFF(void)
{
#ifdef WOLFPROV_DEBUG
    loggingEnabled = 0;
#endif
}

/**
 * Set wolfProv logging level.
 * Default logging level for wolfProv is WP_LOG_LEVEL_DEFAULT.
 *
 * @param levelMask [IN] Bitmask of logging levels from wolfProv_LogType
 *                  in wp_logging.h.
 * @return 0 on success, NOT_COMPILED_IN if debugging has not been enabled.
 */
int wolfProv_SetLogLevel(int levelMask)
{
#ifdef WOLFPROV_DEBUG
    providerLogLevel = levelMask;
    return 0;
#else
    (void)levelMask;
    return NOT_COMPILED_IN;
#endif
}

/**
 * Set which components to log in wolfProv debug logs.
 * Default component level for wolfProv is WP_LOG_COMPONENT_DEFAULT.
 *
 * @param componentMask [IN] Bitmask of components from
 *                      wolfProv_LogComponents in wp_logging.h.
 * @return 0 on success, NOT_COMPILED_IN if debugging has not been enabled.
 */
int wolfProv_SetLogComponents(int componentMask)
{
#ifdef WOLFPROV_DEBUG
    providerLogComponents = componentMask;
    return 0;
#else
    (void)componentMask;
    return NOT_COMPILED_IN;
#endif
}


/**
 * Initialize logging from environment variables with string parsing support.
 */
void wolfProv_InitLoggingFromEnv(void)
{
    const char* debugEnv = XGETENV("WOLFPROV_DEBUG");
    const char* levelEnv = XGETENV("WOLFPROV_LOG_LEVEL");
    const char* componentsEnv = XGETENV("WOLFPROV_LOG_COMPONENTS");
    
    /* Enable debugging if WOLFPROV_DEBUG is set */
    if (debugEnv != NULL && XSTRCMP(debugEnv, "1") == 0) {
        wolfProv_Debugging_ON();
    }
    
    /* Set log level from string or hex */
    if (levelEnv != NULL) {
        int level = wolfProv_ParseLogLevel(levelEnv);
        if (level > 0) {
            wolfProv_SetLogLevel(level);
        }
    }
    
    /* Set components from string list or hex */
    if (componentsEnv != NULL) {
        int components = wolfProv_ParseComponents(componentsEnv);
        if (components > 0) {
            wolfProv_SetLogComponents(components);
        }
    }
}


/**
 * Parse string-based log level to bitmask value.
 *
 * @param levelStr [IN] String representation of log level.
 * @return Bitmask value for the log level.
 */
int wolfProv_ParseLogLevel(const char* levelStr)
{
    if (levelStr == NULL) return 0;
    
    if (XSTRCMP(levelStr, "error") == 0) return WP_LOG_ERROR;
    if (XSTRCMP(levelStr, "enter") == 0) return WP_LOG_ENTER;
    if (XSTRCMP(levelStr, "leave") == 0) return WP_LOG_LEAVE;
    if (XSTRCMP(levelStr, "info") == 0) return WP_LOG_INFO;
    if (XSTRCMP(levelStr, "verbose") == 0) return WP_LOG_VERBOSE;
    if (XSTRCMP(levelStr, "debug") == 0) return WP_LOG_DEBUG;
    if (XSTRCMP(levelStr, "trace") == 0) return WP_LOG_TRACE;
    if (XSTRCMP(levelStr, "full") == 0) return WP_LOG_FULL_DEBUG;
    if (XSTRCMP(levelStr, "full_debug") == 0) return WP_LOG_FULL_DEBUG;
    if (XSTRCMP(levelStr, "all") == 0) return WP_LOG_LEVEL_ALL;
    
    /* Check for combined levels */
    if (XSTRCMP(levelStr, "enter_leave") == 0) return WP_LOG_ENTER | WP_LOG_LEAVE;
    if (XSTRCMP(levelStr, "basic") == 0) return WP_LOG_BASIC;
    if (XSTRCMP(levelStr, "standard") == 0) return WP_LOG_STANDARD;
    if (XSTRCMP(levelStr, "detailed") == 0) return WP_LOG_DETAILED;
    
    /* Try to parse as hex if it starts with 0x */
    if (XSTRNCMP(levelStr, "0x", 2) == 0) {
        /* Simple hex parsing - skip 0x and convert manually */
        const char* hex = levelStr + 2;
        int result = 0;
        while (*hex) {
            if (*hex >= '0' && *hex <= '9') {
                result = result * 16 + (*hex - '0');
            } else if (*hex >= 'a' && *hex <= 'f') {
                result = result * 16 + (*hex - 'a' + 10);
            } else if (*hex >= 'A' && *hex <= 'F') {
                result = result * 16 + (*hex - 'A' + 10);
            } else {
                break;
            }
            hex++;
        }
        return result;
    }
    
    return 0; /* Unknown level */
}

/**
 * Parse string-based component list to bitmask value.
 *
 * @param componentStr [IN] Comma-separated list of component names.
 * @return Bitmask value for the components.
 */
int wolfProv_ParseComponents(const char* componentStr)
{
    int components = 0;
    char* str;
    char* token;
    char* saveptr = NULL;
    
    if (componentStr == NULL) return 0;
    
    /* Handle special cases */
    if (XSTRCMP(componentStr, "all") == 0) return WP_LOG_COMPONENTS_ALL;
    if (XSTRCMP(componentStr, "none") == 0) return 0;
    
    /* Try to parse as hex if it starts with 0x */
    if (XSTRNCMP(componentStr, "0x", 2) == 0) {
        /* Simple hex parsing - skip 0x and convert manually */
        const char* hex = componentStr + 2;
        int result = 0;
        while (*hex) {
            if (*hex >= '0' && *hex <= '9') {
                result = result * 16 + (*hex - '0');
            } else if (*hex >= 'a' && *hex <= 'f') {
                result = result * 16 + (*hex - 'a' + 10);
            } else if (*hex >= 'A' && *hex <= 'F') {
                result = result * 16 + (*hex - 'A' + 10);
            } else {
                break;
            }
            hex++;
        }
        return result;
    }
    
    /* Make a copy for tokenization */
    size_t len = XSTRLEN(componentStr);
    str = XMALLOC(len + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (str == NULL) return 0;
    XMEMCPY(str, componentStr, len + 1);
    
    /* Parse comma-separated component names */
    token = XSTRTOK(str, ",", &saveptr);
    while (token != NULL) {
        /* Trim whitespace */
        while (*token == ' ' || *token == '\t') token++;
        
        if (XSTRCMP(token, "rsa") == 0) components |= WP_LOG_RSA;
        else if (XSTRCMP(token, "ecc") == 0) components |= WP_LOG_ECC;
        else if (XSTRCMP(token, "ecdsa") == 0) components |= WP_LOG_ECDSA;
        else if (XSTRCMP(token, "ecdh") == 0) components |= WP_LOG_ECDH;
        else if (XSTRCMP(token, "dh") == 0) components |= WP_LOG_DH;
        else if (XSTRCMP(token, "aes") == 0) components |= WP_LOG_AES;
        else if (XSTRCMP(token, "des") == 0) components |= WP_LOG_DES;
        else if (XSTRCMP(token, "sha") == 0) components |= WP_LOG_SHA;
        else if (XSTRCMP(token, "md5") == 0) components |= WP_LOG_MD5;
        else if (XSTRCMP(token, "hmac") == 0) components |= WP_LOG_HMAC;
        else if (XSTRCMP(token, "cmac") == 0) components |= WP_LOG_CMAC;
        else if (XSTRCMP(token, "hkdf") == 0) components |= WP_LOG_HKDF;
        else if (XSTRCMP(token, "pbkdf2") == 0) components |= WP_LOG_PBKDF2;
        else if (XSTRCMP(token, "krb5kdf") == 0) components |= WP_LOG_KRB5KDF;
        else if (XSTRCMP(token, "drbg") == 0) components |= WP_LOG_DRBG;
        else if (XSTRCMP(token, "x25519") == 0) components |= WP_LOG_X25519;
        else if (XSTRCMP(token, "x448") == 0) components |= WP_LOG_X448;
        else if (XSTRCMP(token, "ed25519") == 0) components |= WP_LOG_ED25519;
        else if (XSTRCMP(token, "ed448") == 0) components |= WP_LOG_ED448;
        else if (XSTRCMP(token, "query") == 0) components |= WP_LOG_QUERY;
        else if (XSTRCMP(token, "provider") == 0) components |= WP_LOG_PROVIDER;
        else if (XSTRCMP(token, "rng") == 0) components |= WP_LOG_RNG;
        else if (XSTRCMP(token, "digest") == 0) components |= WP_LOG_DIGEST;
        else if (XSTRCMP(token, "mac") == 0) components |= WP_LOG_MAC;
        else if (XSTRCMP(token, "cipher") == 0) components |= WP_LOG_CIPHER;
        else if (XSTRCMP(token, "pk") == 0) components |= WP_LOG_PK;
        else if (XSTRCMP(token, "ke") == 0) components |= WP_LOG_KE;
        else if (XSTRCMP(token, "kdf") == 0) components |= WP_LOG_KDF;
        
        token = XSTRTOK(NULL, ",", &saveptr);
    }
    
    XFREE(str, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return components;
}

#ifdef WOLFPROV_DEBUG

/**
 * Logging function used by wolfProv.
 * Calls either default log mechanism or application-registered logging
 * callback.
 *
 * @param logLevel   [IN] Log level.
 * @param logMessage [IN] Log message.
 */
static void wolfprovider_log(const int logLevel, const int component,
                           const char *const logMessage)
{
    /* Don't log messages that do not match our current logging level */
    if ((providerLogLevel & logLevel) != logLevel)
        return;

    /* Don't log messages from components that do not match enabled list */
    if ((providerLogComponents & component) != component)
        return;

    if (log_function) {
        log_function(logLevel, component, logMessage);
    }
    else {
#if defined(WOLFPROV_USER_LOG)
        WOLFPROV_USER_LOG(logMessage);
#elif defined(WOLFPROV_LOG_PRINTF)
        printf("%s\n", logMessage);
#else
        fprintf(stderr, "%s\n", logMessage);
#endif
    }
}

/**
 * Internal log function for printing varg messages to a specific
 * log level. Used by WOLFPROV_MSG and WOLFPROV_MSG_VERBOSE.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param logLevel [IN] Log level, from wolfProv_LogType enum.
 * @param fmt   [IN] Log message format string.
 * @param vargs [IN] Variable arguments, used with format string, fmt.
 */
WP_PRINTF_FUNC(3, 0)
static void wolfprovider_msg_internal(int component, int logLevel,
                                    const char* fmt, va_list vlist)
{
    char msgStr[WOLFPROV_MAX_LOG_WIDTH];

    if (loggingEnabled) {
        XVSNPRINTF(msgStr, sizeof(msgStr), fmt, vlist);
        wolfprovider_log(logLevel, component, msgStr);
    }
}

/**
 * Log function for general messages.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param fmt   [IN] Log message format string.
 * @param vargs [IN] Variable arguments, used with format string, fmt.
 */
WP_PRINTF_FUNC(2, 3)
void WOLFPROV_MSG(int component, const char* fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    wolfprovider_msg_internal(component, WP_LOG_INFO, fmt, vlist);
    va_end(vlist);
}

/**
 * Log function for general messages, prints to WP_LOG_VERBOSE level.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param fmt   [IN] Log message format string.
 * @param vargs [IN] Variable arguments, used with format string, fmt.
 */
WP_PRINTF_FUNC(2, 3)
void WOLFPROV_MSG_VERBOSE(int component, const char* fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    wolfprovider_msg_internal(component, WP_LOG_VERBOSE, fmt, vlist);
    va_end(vlist);
}

/**
 * Log function for debug messages, prints to WP_LOG_DEBUG level.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param fmt   [IN] Log message format string.
 * @param vargs [IN] Variable arguments, used with format string, fmt.
 */
WP_PRINTF_FUNC(2, 3)
void WOLFPROV_MSG_DEBUG(int component, const char* fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    wolfprovider_msg_internal(component, WP_LOG_DEBUG, fmt, vlist);
    va_end(vlist);
}

/**
 * Log function for trace messages, prints to WP_LOG_TRACE level.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param fmt   [IN] Log message format string.
 * @param vargs [IN] Variable arguments, used with format string, fmt.
 */
WP_PRINTF_FUNC(2, 3)
void WOLFPROV_MSG_TRACE(int component, const char* fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    wolfprovider_msg_internal(component, WP_LOG_TRACE, fmt, vlist);
    va_end(vlist);
}

/**
 * Log function used to record function entry.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param msg  [IN] Log message.
 */
void WOLFPROV_ENTER(int component, const char* msg)
{
    if (loggingEnabled) {
        char buffer[WOLFPROV_MAX_LOG_WIDTH];
        XSNPRINTF(buffer, sizeof(buffer), "wolfProv Entering %s", msg);
        wolfprovider_log(WP_LOG_ENTER, component, buffer);
    }
}

/**
 * Log function used to record function exit. Extended for function name.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param func [IN] Name of function that exiting.
 * @param msg  [IN] Log message.
 * @param ret  [IN] Value that function will be returning.
 */
void WOLFPROV_LEAVE_EX(int component, const char* func, const char* msg,
    int ret)
{
    if (loggingEnabled) {
        char buffer[WOLFPROV_MAX_LOG_WIDTH];
        XSNPRINTF(buffer, sizeof(buffer), "wolfProv Leaving %s, return %d (%s)",
                  msg, ret, func);
        wolfprovider_log(WP_LOG_LEAVE, component, buffer);
    }
}

/**
 * Log function for error code, general error message.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param error  [IN] error code to be logged.
 * @param file   [IN] Source file where error is called.
 * @param line   [IN] Line in source file where error is called.
 */
void WOLFPROV_ERROR_LINE(int component, int error, const char* file, int line)
{
    if (loggingEnabled) {
        char buffer[WOLFPROV_MAX_LOG_WIDTH];
        XSNPRINTF(buffer, sizeof(buffer),
                  "%s:%d - wolfProv error occurred, error = %d", file, line,
                  error);
        wolfprovider_log(WP_LOG_ERROR, component, buffer);
    }
}

/**
 * Log function for error message.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param msg  [IN] Error message.
 * @param file [IN] Source file where error is called.
 * @param line [IN] Line in source file where error is called.
 */
void WOLFPROV_ERROR_MSG_LINE(int component, const char* msg,
                               const char* file, int line)
{
    if (loggingEnabled) {
        char buffer[WOLFPROV_MAX_LOG_WIDTH];
        XSNPRINTF(buffer, sizeof(buffer), "%s:%d - wolfProv Error %s",
                  file, line, msg);
        wolfprovider_log(WP_LOG_ERROR, component, buffer);
    }
}

/**
 * Log function to convey function name and error for functions returning an
 * integer return code.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param funcName  [IN] Name of function called.
 * @param ret       [IN] Return of function.
 * @param file      [IN] Source file where error is called.
 * @param line      [IN] Line in source file where error is called.
 */
void WOLFPROV_ERROR_FUNC_LINE(int component, const char* funcName, int ret,
                                const char* file, int line)
{
    if (loggingEnabled) {
        char buffer[WOLFPROV_MAX_LOG_WIDTH];
        XSNPRINTF(buffer, sizeof(buffer),
                  "%s:%d - Error calling %s: ret = %d", file, line, funcName,
                  ret);
        wolfprovider_log(WP_LOG_ERROR, component, buffer);
    }
}

/**
 * Log function to convey function name and error for functions returning a
 * pointer.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param funcName  [IN] Name of function called.
 * @param ret       [IN] Return of function.
 * @param file      [IN] Source file where error is called.
 * @param line      [IN] Line in source file where error is called.
 */
void WOLFPROV_ERROR_FUNC_NULL_LINE(int component, const char* funcName,
                                     const void *ret, const char* file,
                                     int line)
{
    if (loggingEnabled) {
        char buffer[WOLFPROV_MAX_LOG_WIDTH];
        XSNPRINTF(buffer, sizeof(buffer),
                  "%s:%d - Error calling %s: ret = %p", file, line, funcName,
                  ret);
        wolfprovider_log(WP_LOG_ERROR, component, buffer);
    }
}

/* Macro to control line length of WOLFPROV_BUFFER, for number of
 * both bytes and chars to print on one line. */
#ifndef WOLFPROV_LINE_LEN
#define WOLFPROV_LINE_LEN 16
#endif

/**
 * Log function to print buffer.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param buffer  [IN] Buffer to print.
 * @param length  [IN] Length of buffer, octets.
 */
void WOLFPROV_BUFFER(int component, const unsigned char* buffer,
                       unsigned int length)
{
    int i, buflen = (int)length, bufidx;
    char line[(WOLFPROV_LINE_LEN * 4) + 3]; /* \t00..0F | chars...chars\0 */


    if (!loggingEnabled) {
        return;
    }

    if (!buffer) {
        wolfprovider_log(WP_LOG_VERBOSE, component, "\tNULL");
        return;
    }

    while (buflen > 0) {
        bufidx = 0;
        XSNPRINTF(&line[bufidx], sizeof(line)-bufidx, "\t");
        bufidx++;

        for (i = 0; i < WOLFPROV_LINE_LEN; i++) {
            if (i < buflen) {
                XSNPRINTF(&line[bufidx], sizeof(line)-bufidx, "%02x ",
                          buffer[i]);
            }
            else {
                XSNPRINTF(&line[bufidx], sizeof(line)-bufidx, "   ");
            }
            bufidx += 3;
        }

        XSNPRINTF(&line[bufidx], sizeof(line)-bufidx, "| ");
        bufidx++;

        for (i = 0; i < WOLFPROV_LINE_LEN; i++) {
            if (i < buflen) {
                XSNPRINTF(&line[bufidx], sizeof(line)-bufidx,
                     "%c", 31 < buffer[i] && buffer[i] < 127 ? buffer[i] : '.');
                bufidx++;
            }
        }

        wolfprovider_log(WP_LOG_VERBOSE, component, line);
        buffer += WOLFPROV_LINE_LEN;
        buflen -= WOLFPROV_LINE_LEN;
    }
}


/**
 * Enable a specific logging component.
 *
 * @param component [IN] Component to enable from wolfProv_LogComponents enum.
 * @return 0 on success, NOT_COMPILED_IN if debugging has not been enabled.
 */
int wolfProv_EnableComponent(int component)
{
#ifdef WOLFPROV_DEBUG
    providerLogComponents |= component;
#else
    (void)component;
#endif
    return 0;
}

/**
 * Disable a specific logging component.
 *
 * @param component [IN] Component to disable from wolfProv_LogComponents enum.
 * @return 0 on success, NOT_COMPILED_IN if debugging has not been enabled.
 */
int wolfProv_DisableComponent(int component)
{
#ifdef WOLFPROV_DEBUG
    providerLogComponents &= ~component;
#else
    (void)component;
#endif
    return 0;
}

/**
 * Check if a specific logging component is enabled.
 *
 * @param component [IN] Component to check from wolfProv_LogComponents enum.
 * @return 1 if enabled, 0 if disabled or not compiled in.
 */
int wolfProv_IsComponentEnabled(int component)
{
#ifdef WOLFPROV_DEBUG
    return (providerLogComponents & component) != 0;
#else
    (void)component;
    return 0;
#endif
}

/**
 * Set verbosity level using convenience constants.
 *
 * @param level [IN] Verbosity level from wolfProv_LogType convenience constants.
 * @return 0 on success, NOT_COMPILED_IN if debugging has not been enabled.
 */
int wolfProv_SetVerbosityLevel(int level)
{
#ifdef WOLFPROV_DEBUG
    providerLogLevel = level;
#else
    (void)level;
#endif
    return 0;
}

/**
 * Get current verbosity level.
 *
 * @return Current verbosity level, 0 if not compiled in.
 */
int wolfProv_GetVerbosityLevel(void)
{
#ifdef WOLFPROV_DEBUG
    return providerLogLevel;
#else
    return 0;
#endif
}

/**
 * Enable logging for a specific algorithm by name.
 *
 * @param algorithm [IN] Algorithm name string (e.g., "RSA", "AES", "SHA").
 * @return 0 on success, -1 if unknown algorithm, NOT_COMPILED_IN if debugging not enabled.
 */
int wolfProv_EnableAlgorithm(const char* algorithm)
{
#ifdef WOLFPROV_DEBUG
    if (algorithm == NULL) return -1;
    
    if (XSTRCMP(algorithm, "RSA") == 0) return wolfProv_EnableComponent(WP_LOG_RSA);
    if (XSTRCMP(algorithm, "ECC") == 0) return wolfProv_EnableComponent(WP_LOG_ECC);
    if (XSTRCMP(algorithm, "DH") == 0) return wolfProv_EnableComponent(WP_LOG_DH);
    if (XSTRCMP(algorithm, "AES") == 0) return wolfProv_EnableComponent(WP_LOG_AES);
    if (XSTRCMP(algorithm, "DES") == 0) return wolfProv_EnableComponent(WP_LOG_DES);
    if (XSTRCMP(algorithm, "SHA") == 0) return wolfProv_EnableComponent(WP_LOG_SHA);
    if (XSTRCMP(algorithm, "MD5") == 0) return wolfProv_EnableComponent(WP_LOG_MD5);
    if (XSTRCMP(algorithm, "HMAC") == 0) return wolfProv_EnableComponent(WP_LOG_HMAC);
    if (XSTRCMP(algorithm, "CMAC") == 0) return wolfProv_EnableComponent(WP_LOG_CMAC);
    if (XSTRCMP(algorithm, "HKDF") == 0) return wolfProv_EnableComponent(WP_LOG_HKDF);
    if (XSTRCMP(algorithm, "PBKDF2") == 0) return wolfProv_EnableComponent(WP_LOG_PBKDF2);
    if (XSTRCMP(algorithm, "KRB5KDF") == 0) return wolfProv_EnableComponent(WP_LOG_KRB5KDF);
    if (XSTRCMP(algorithm, "DRBG") == 0) return wolfProv_EnableComponent(WP_LOG_DRBG);
    if (XSTRCMP(algorithm, "ECDSA") == 0) return wolfProv_EnableComponent(WP_LOG_ECDSA);
    if (XSTRCMP(algorithm, "ECDH") == 0) return wolfProv_EnableComponent(WP_LOG_ECDH);
    if (XSTRCMP(algorithm, "ED25519") == 0) return wolfProv_EnableComponent(WP_LOG_ED25519);
    if (XSTRCMP(algorithm, "ED448") == 0) return wolfProv_EnableComponent(WP_LOG_ED448);
    if (XSTRCMP(algorithm, "X25519") == 0) return wolfProv_EnableComponent(WP_LOG_X25519);
    if (XSTRCMP(algorithm, "X448") == 0) return wolfProv_EnableComponent(WP_LOG_X448);
    if (XSTRCMP(algorithm, "QUERY") == 0) return wolfProv_EnableComponent(WP_LOG_QUERY);
    
    return -1;
#else
    (void)algorithm;
    return 0;
#endif
}

/**
 * Disable logging for a specific algorithm by name.
 *
 * @param algorithm [IN] Algorithm name string (e.g., "RSA", "AES", "SHA").
 * @return 0 on success, -1 if unknown algorithm, NOT_COMPILED_IN if debugging not enabled.
 */
int wolfProv_DisableAlgorithm(const char* algorithm)
{
#ifdef WOLFPROV_DEBUG
    if (algorithm == NULL) return -1;
    
    if (XSTRCMP(algorithm, "RSA") == 0) return wolfProv_DisableComponent(WP_LOG_RSA);
    if (XSTRCMP(algorithm, "ECC") == 0) return wolfProv_DisableComponent(WP_LOG_ECC);
    if (XSTRCMP(algorithm, "DH") == 0) return wolfProv_DisableComponent(WP_LOG_DH);
    if (XSTRCMP(algorithm, "AES") == 0) return wolfProv_DisableComponent(WP_LOG_AES);
    if (XSTRCMP(algorithm, "DES") == 0) return wolfProv_DisableComponent(WP_LOG_DES);
    if (XSTRCMP(algorithm, "SHA") == 0) return wolfProv_DisableComponent(WP_LOG_SHA);
    if (XSTRCMP(algorithm, "MD5") == 0) return wolfProv_DisableComponent(WP_LOG_MD5);
    if (XSTRCMP(algorithm, "HMAC") == 0) return wolfProv_DisableComponent(WP_LOG_HMAC);
    if (XSTRCMP(algorithm, "CMAC") == 0) return wolfProv_DisableComponent(WP_LOG_CMAC);
    if (XSTRCMP(algorithm, "HKDF") == 0) return wolfProv_DisableComponent(WP_LOG_HKDF);
    if (XSTRCMP(algorithm, "PBKDF2") == 0) return wolfProv_DisableComponent(WP_LOG_PBKDF2);
    if (XSTRCMP(algorithm, "KRB5KDF") == 0) return wolfProv_DisableComponent(WP_LOG_KRB5KDF);
    if (XSTRCMP(algorithm, "DRBG") == 0) return wolfProv_DisableComponent(WP_LOG_DRBG);
    if (XSTRCMP(algorithm, "ECDSA") == 0) return wolfProv_DisableComponent(WP_LOG_ECDSA);
    if (XSTRCMP(algorithm, "ECDH") == 0) return wolfProv_DisableComponent(WP_LOG_ECDH);
    if (XSTRCMP(algorithm, "ED25519") == 0) return wolfProv_DisableComponent(WP_LOG_ED25519);
    if (XSTRCMP(algorithm, "ED448") == 0) return wolfProv_DisableComponent(WP_LOG_ED448);
    if (XSTRCMP(algorithm, "X25519") == 0) return wolfProv_DisableComponent(WP_LOG_X25519);
    if (XSTRCMP(algorithm, "X448") == 0) return wolfProv_DisableComponent(WP_LOG_X448);
    if (XSTRCMP(algorithm, "QUERY") == 0) return wolfProv_DisableComponent(WP_LOG_QUERY);
    
    return -1;
#else
    (void)algorithm;
    return 0;
#endif
}

#else /* !WOLFPROV_DEBUG */

#endif /* WOLFPROV_DEBUG */


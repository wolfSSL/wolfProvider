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

/* Callback functions to parse environment variables WOLFPROV_LOG_LEVEL and WOLFPROV_LOG_COMPONENTS */
static void wolfProv_LogLevelToMask(const char* level, size_t len, void* ctx);
static void wolfProv_LogComponentToMask(const char* level, size_t len, void* ctx);

/* Callback receives a pointer to the token (valid only during this call),
 * the token length (excluding the trailing '\0'), and an opaque context.
 */
typedef void (*token_cb)(const char *token, size_t len, void *ctx);
/* Parse environment variables WOLFPROV_LOG_LEVEL and WOLFPROV_LOG_COMPONENTS 
 * in the form (WP_LOG_ERROR | WP_LOG_LEAVE). 
 * See wp_logging.h for valid values */
static int wolfProv_TokenParse(const char *input, const char *delims,
    token_cb cb, void* ctx);

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

int wolfProv_LogInit(void)
{
#ifdef WOLFPROV_DEBUG
#if defined(XGETENV) && !defined(NO_GETENV)
    uint32_t level = 0;
    uint32_t components = 0;
    char* logLevelStr = XGETENV("WOLFPROV_LOG_LEVEL");
    char* logComponentsStr = XGETENV("WOLFPROV_LOG_COMPONENTS");

    if (logLevelStr != NULL) {
        if (wolfProv_TokenParse(logLevelStr, "()| \t", wolfProv_LogLevelToMask, 
                &level) == 0) {
            WOLFPROV_MSG(WP_LOG_PROVIDER,
                "Setting WOLFPROV_LOG_LEVEL to 0x%X", level);
            providerLogLevel = level;
        }
        else {
            WOLFPROV_MSG(WP_LOG_PROVIDER,
                "WOLFPROV_LOG_LEVEL environment variable too long or missing, "
                    "ignoring it");
        }
    }
    if (logComponentsStr != NULL) {
        if (wolfProv_TokenParse(logComponentsStr, "()| \t", 
                wolfProv_LogComponentToMask, &components) == 0) {
            WOLFPROV_MSG(WP_LOG_PROVIDER,
                "Setting WOLFPROV_LOG_COMPONENTS to 0x%X", components);
            providerLogComponents = components;
        }
        else {
            WOLFPROV_MSG(WP_LOG_PROVIDER,
                "WOLFPROV_LOG_COMPONENTS environment variable too long or "
                    "missing, ignoring it");
        }
    }
#endif
#endif
    return 0;
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
    /* Check compile-time configuration first */
    if (!WOLFPROV_COMPILE_TIME_CHECK(component, logLevel)) {
        return;
    }

    /* Don't log messages that do not match our current logging level */
    if ((providerLogLevel & logLevel) != logLevel) {
        return;
    }

    /* Don't log messages from components that do not match enabled list */
    if ((providerLogComponents & component) != component) {
        return;
    }

    if (log_function) {
        log_function(logLevel, component, logMessage);
    }
    else {
#if defined(WOLFPROV_USER_LOG)
        WOLFPROV_USER_LOG(logMessage);
#elif defined(WOLFPROV_LOG_PRINTF)
        printf("%s\n", logMessage);
#elif defined(WOLFPROV_LOG_FILE)
        {
            /* Persistent file handle for logging to file */
            static XFILE* logFileHandle = NULL;
            /* Flag to track if we've already reported file open failure to avoid spam */
            static int logFileErrorReported = 0;

            if (logFileHandle == NULL) {
                logFileHandle = XFOPEN(WOLFPROV_LOG_FILE, "a");
                if (logFileHandle) {
                    XFPRINTF(stderr, "wolfProvider: Using log file %s\n", 
                        WOLFPROV_LOG_FILE);
                    fflush(stderr);
                }
                else {
                    /* Fall back to stderr when file open fails */
                    logFileHandle = stderr;
                    /* Only report file error once to avoid spam */
                    if (!logFileErrorReported) {
                        logFileErrorReported = 1;
                        XFPRINTF(stderr, "wolfProvider: Log file not open: %s, "
                                "falling back to stderr\n", 
                            WOLFPROV_LOG_FILE);
                    }
                }
            }
            
            XFWRITE(logMessage, strlen(logMessage), 1, logFileHandle);
            XFWRITE("\n", 1, 1, logFileHandle);
            XFFLUSH(logFileHandle);
        }
#else
        XFPRINTF(stderr, "%s\n", logMessage);
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
 * Log function for debug messages with return code, prints to WP_LOG_DEBUG level.
 * Unified function to reduce code duplication for common "function failed with rc=%d" pattern.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param func_name [IN] Name of the function that failed.
 * @param rc       [IN] Return code value.
 */
void WOLFPROV_MSG_DEBUG_RETCODE(int component, const char* func_name, int rc)
{
    WOLFPROV_MSG_DEBUG(component, "%s failed with rc=%d", func_name, rc);
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
        XSNPRINTF(buffer, sizeof(buffer), 
            "wolfProv Entering %s", msg);
        wolfprovider_log(WP_LOG_ENTER, component, buffer);
    }
}

/**
 * Log function used to record function entry for check functions.
 * These functions use WOLFPROV_LEAVE_SILENT and may not show up in logs.
 * The "[leaving silently]" prefix indicates that exit logging may be suppressed.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param msg  [IN] Log message.
 */
void WOLFPROV_ENTER_SILENT(int component, const char* msg)
{
#ifdef WOLFPROV_LEAVE_SILENT_MODE
    if (loggingEnabled) {
        char buffer[WOLFPROV_MAX_LOG_WIDTH];
        XSNPRINTF(buffer, sizeof(buffer), 
            "wolfProv Entering [leaving silently] %s", msg);
        wolfprovider_log(WP_LOG_ENTER, component, buffer);
    }
#else
    WOLFPROV_ENTER(component, msg);
#endif
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
        XSNPRINTF(buffer, sizeof(buffer), 
            "wolfProv Leaving %s, return %d (%s)", msg, ret, func);
        wolfprovider_log(WP_LOG_LEAVE, component, buffer);
    }
}

/**
 * Log function to suppress LEAVE messages. This function only prints if
 * ret == 1. All other cases are suppressed by default to reduce noise from
 * probe failures. Define WOLFPROV_LEAVE_SILENT to enable this logic.
 *
 * @param component [IN] Component type, from wolfProv_LogComponents enum.
 * @param func    [IN] Name of function that is exiting.
 * @param msg     [IN] Log message (typically file:line).
 * @param ret     [IN] Value that function will be returning.
 */
void WOLFPROV_LEAVE_SILENT_EX(int component, const char* func, 
                              const char* msg, int ret)
{
#ifdef WOLFPROV_LEAVE_SILENT_MODE
        /* Success - always print */
        if (ret == 1) {
            WOLFPROV_LEAVE_EX(component, func, msg, ret);
        }
        else {
            /* Anything else is suppressed */
        }
#else
        /* Legacy behavior: log all returns including return 0 */
        WOLFPROV_LEAVE_EX(component, func, msg, ret);
#endif
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
        XSNPRINTF(buffer, sizeof(buffer), 
            "%s:%d - wolfProv Error %s", file, line, msg);
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

static void wolfProv_LogLevelToMask(const char* level, size_t len, void* ctx) {
    /* Map strings to enum values. 
     * Ensure this table is kept in sync with the enum in wp_logging.h */
    static const struct {
        const char* name;
        size_t      len;
        uint32_t    mask;
    } log_levels[] = {
        { "WP_LOG_ERROR",     XSTRLEN("WP_LOG_ERROR"),  WP_LOG_ERROR   },
        { "WP_LOG_ENTER",     XSTRLEN("WP_LOG_ENTER"),  WP_LOG_ENTER   },
        { "WP_LOG_LEAVE",     XSTRLEN("WP_LOG_LEAVE"),  WP_LOG_LEAVE   },
        { "WP_LOG_INFO",      XSTRLEN("WP_LOG_INFO"),   WP_LOG_INFO    },
        { "WP_LOG_VERBOSE",   XSTRLEN("WP_LOG_VERBOSE"),WP_LOG_VERBOSE },
        { "WP_LOG_DEBUG",     XSTRLEN("WP_LOG_DEBUG"),  WP_LOG_DEBUG   },
        { "WP_LOG_TRACE",     XSTRLEN("WP_LOG_TRACE"),  WP_LOG_TRACE   },
        { "WP_LOG_LEVEL_DEFAULT",
                              XSTRLEN("WP_LOG_LEVEL_DEFAULT"),
                                                    WP_LOG_LEVEL_DEFAULT },
        { "WP_LOG_LEVEL_ALL",
                              XSTRLEN("WP_LOG_LEVEL_ALL"),
                                                    WP_LOG_LEVEL_ALL },
    };
    static const size_t num_levels = sizeof(log_levels) / sizeof(log_levels[0]);
    uint32_t *mask = (uint32_t *)ctx;

    for (size_t i = 0; i < num_levels; ++i) {
        if (log_levels[i].len == len &&
            XSTRNCMP(level, log_levels[i].name, len) == 0) {
            *mask |= log_levels[i].mask;
            break;
        }
    }
}

static void wolfProv_LogComponentToMask(const char* level, size_t len, void* ctx) {
    /* Map strings to enum values. 
     * Ensure this table is kept in sync with the enum in wp_logging.h */
    static const struct {
        const char* name;
        size_t      len;
        uint32_t    mask;
    } log_components[] = {
        { "WP_LOG_RNG",         XSTRLEN("WP_LOG_RNG"),        WP_LOG_RNG      },
        { "WP_LOG_DIGEST",      XSTRLEN("WP_LOG_DIGEST"),     WP_LOG_DIGEST   },
        { "WP_LOG_MAC",         XSTRLEN("WP_LOG_MAC"),        WP_LOG_MAC      },
        { "WP_LOG_CIPHER",      XSTRLEN("WP_LOG_CIPHER"),     WP_LOG_CIPHER   },
        { "WP_LOG_PK",          XSTRLEN("WP_LOG_PK"),         WP_LOG_PK       },
        { "WP_LOG_KE",          XSTRLEN("WP_LOG_KE"),         WP_LOG_KE       },
        { "WP_LOG_KDF",         XSTRLEN("WP_LOG_KDF"),        WP_LOG_KDF      },
        { "WP_LOG_PROVIDER",    XSTRLEN("WP_LOG_PROVIDER"),   WP_LOG_PROVIDER },
        { "WP_LOG_RSA",         XSTRLEN("WP_LOG_RSA"),        WP_LOG_RSA      },
        { "WP_LOG_ECC",         XSTRLEN("WP_LOG_ECC"),        WP_LOG_ECC      },
        { "WP_LOG_DH",          XSTRLEN("WP_LOG_DH"),         WP_LOG_DH       },
        { "WP_LOG_AES",         XSTRLEN("WP_LOG_AES"),        WP_LOG_AES      },
        { "WP_LOG_DES",         XSTRLEN("WP_LOG_DES"),        WP_LOG_DES      },
        { "WP_LOG_SHA",         XSTRLEN("WP_LOG_SHA"),        WP_LOG_SHA      },
        { "WP_LOG_MD5",         XSTRLEN("WP_LOG_MD5"),        WP_LOG_MD5      },
        { "WP_LOG_HMAC",        XSTRLEN("WP_LOG_HMAC"),       WP_LOG_HMAC     },
        { "WP_LOG_CMAC",        XSTRLEN("WP_LOG_CMAC"),       WP_LOG_CMAC     },
        { "WP_LOG_HKDF",        XSTRLEN("WP_LOG_HKDF"),       WP_LOG_HKDF     },
        { "WP_LOG_PBKDF2",      XSTRLEN("WP_LOG_PBKDF2"),     WP_LOG_PBKDF2   },
        { "WP_LOG_KRB5KDF",     XSTRLEN("WP_LOG_KRB5KDF"),    WP_LOG_KRB5KDF  },
        { "WP_LOG_DRBG",        XSTRLEN("WP_LOG_DRBG"),       WP_LOG_DRBG     },
        { "WP_LOG_ECDSA",       XSTRLEN("WP_LOG_ECDSA"),      WP_LOG_ECDSA    },
        { "WP_LOG_ECDH",        XSTRLEN("WP_LOG_ECDH"),       WP_LOG_ECDH     },
        { "WP_LOG_ED25519",     XSTRLEN("WP_LOG_ED25519"),    WP_LOG_ED25519  },
        { "WP_LOG_ED448",       XSTRLEN("WP_LOG_ED448"),      WP_LOG_ED448    },
        { "WP_LOG_X25519",      XSTRLEN("WP_LOG_X25519"),     WP_LOG_X25519   },
        { "WP_LOG_X448",        XSTRLEN("WP_LOG_X448"),       WP_LOG_X448     },
        { "WP_LOG_QUERY",       XSTRLEN("WP_LOG_QUERY"),      WP_LOG_QUERY    },
        { "WP_LOG_TLS1_PRF",     XSTRLEN("WP_LOG_TLS1_PRF"),   WP_LOG_TLS1_PRF },
        { "WP_LOG_COMPONENTS_ALL",
                                XSTRLEN("WP_LOG_COMPONENTS_ALL"),
                                                        WP_LOG_COMPONENTS_ALL },
        { "WP_LOG_COMPONENTS_DEFAULT",
                                XSTRLEN("WP_LOG_COMPONENTS_DEFAULT"),
                                                        WP_LOG_COMPONENTS_DEFAULT },
    };
    static const size_t num_components =
        sizeof(log_components) / sizeof(log_components[0]);
    uint32_t *mask = (uint32_t *)ctx;

    for (size_t i = 0; i < num_components; ++i) {
        if (log_components[i].len == len &&
            XSTRNCMP(level, log_components[i].name, len) == 0) {
            *mask |= log_components[i].mask;
            break;
        }
    }
}

/* Returns number of tokens passed to cb,
 *  0 if input is NULL or empty,
 * -1 on allocation failure.
 */
static int wolfProv_TokenParse(const char *input,
                      const char *delims,   /* e.g. "()| \t" */
                      token_cb cb,
                      void *ctx)  /* opaque context passed to cb */
{
    if (!cb || !delims) return -1;
    if (!input || !*input) return 0;

    char token[256];
    size_t n = XSTRLEN(input);

    if (n < sizeof(token)) {
        /* Copy the input string to a writable buffer, including the trailing '\0' */
        XSTRNCPY(token, input, n + 1);
    }
    else {
        return -1;
    }

    /* Overwrite delimiters with '\0' using a simple nested loop. */
    for (size_t i = 0; i < n; ++i) {
        for (const char *d = delims; *d; ++d) {
            if (token[i] == *d) {
                token[i] = '\0';
                break;
            }
        }
    }

    /* Walk tokens: skip runs of NULs, emit non-empty spans. */
    for (size_t i = 0; i <= n; i++) {   
        if (token[i] == '\0') {
            continue;  /* skip empties */
        }
        size_t len = strlen(&token[i]);
        cb(&token[i], len, ctx);
        i += len; /* hop past this token */
    }

    return 0;
}

#endif /* WOLFPROV_DEBUG */


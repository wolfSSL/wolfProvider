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

#endif /* WOLFPROV_DEBUG */


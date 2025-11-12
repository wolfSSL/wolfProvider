/* test_logging.c
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

#include <stdlib.h>
#include <wolfprovider/alg_funcs.h>
#include "unit.h"

/******************************************************************************/

#ifdef WOLFPROV_DEBUG
typedef struct TestLogState {
    int called;
    int lastLevel;
    int lastComponent;
    char lastMsg[256];
} TestLogState;

static TestLogState gLog;

static void test_log_cb(const int level, const int component,
    const char *const msg)
{
    gLog.called++;
    gLog.lastLevel = level;
    gLog.lastComponent = component;
    XSTRNCPY(gLog.lastMsg, msg, sizeof(gLog.lastMsg) - 1);
    gLog.lastMsg[sizeof(gLog.lastMsg) - 1] = '\0';
}

static void reset_env_and_init(const char* levelStr, const char* compStr)
{
    (void)setenv("WOLFPROV_LOG_LEVEL", levelStr, 1);
    (void)setenv("WOLFPROV_LOG_COMPONENTS", compStr, 1);
    /* Clear runtime masks so env takes effect even if parser ignores */
    (void)wolfProv_SetLogLevel(0);
    (void)wolfProv_SetLogComponents(0);
    (void)wolfProv_LogInit();
    (void)wolfProv_Debugging_ON();
    XMEMSET(&gLog, 0, sizeof(gLog));
}

#define CHECK_LOGGED(prevCount, lvlConst, compConst, nameStr) do { \
    /* Only assert if compile-time filters allow this level+component */ \
    if (((WOLFPROV_LOG_COMPONENTS_FILTER & (compConst)) != 0) && \
        ((WOLFPROV_LOG_LEVEL_FILTER & (lvlConst)) != 0)) { \
        if (gLog.called <= (prevCount)) {\
            PRINT_ERR_MSG("Too few logs captured for %s", (nameStr)); \
            rc = -1; \
        } \
        else if (gLog.lastLevel != (lvlConst)) { \
            PRINT_ERR_MSG("Expected %s log to be captured at level %d, got %d", (nameStr), (lvlConst), (gLog.lastLevel)); \
            rc = -1; \
        } \
        else if (gLog.lastComponent != (compConst)) { \
            PRINT_ERR_MSG("Expected %s log to be captured at component %d, got %d", (nameStr), (compConst), (gLog.lastComponent)); \
            rc = -1; \
        } \
    } \
} while (0)

#define CHECK_NOT_LOGGED(prevCount, lvlConst, compConst, nameStr) do { \
    /* Only assert if compile-time filters allow this level+component */ \
    if (((WOLFPROV_LOG_COMPONENTS_FILTER & (compConst)) != 0) && \
        ((WOLFPROV_LOG_LEVEL_FILTER & (lvlConst)) != 0)) { \
        if (gLog.called != (prevCount)) { \
            PRINT_ERR_MSG("Expected %s log to be filtered out", (nameStr)); \
            rc = -1; \
        } \
    } \
} while (0)
#endif

int test_logging(void *data)
{
    (void)data;

#ifndef WOLFPROV_DEBUG
    /* Logging not compiled in; treat as skipped */
    PRINT_MSG("WOLFPROV_DEBUG not enabled; skipping logging test");
    return 0;
#else
    int ret;
    int rc = 0;

    XMEMSET(&gLog, 0, sizeof(gLog));

    ret = wolfProv_SetLoggingCb(test_log_cb);
    if (ret != 0) {
        PRINT_ERR_MSG("wolfProv_SetLoggingCb failed: %d", ret);
        return -1;
    }

    /* Scenario A: ALL levels, provider component */
    reset_env_and_init("WP_LOG_LEVEL_ALL", "WP_LOG_COMP_PROVIDER");
    {
        int prev;
        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_PROVIDER, "info A");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_PROVIDER, "INFO (A)");

        prev = gLog.called; WOLFPROV_ERROR(WP_LOG_COMP_PROVIDER, -100);
        CHECK_LOGGED(prev, WP_LOG_LEVEL_ERROR, WP_LOG_COMP_PROVIDER, "ERROR (A)");

        prev = gLog.called; WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "funcA");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_ENTER, WP_LOG_COMP_PROVIDER, "ENTER (A)");

        prev = gLog.called; WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, "funcA", 0);
        CHECK_LOGGED(prev, WP_LOG_LEVEL_LEAVE, WP_LOG_COMP_PROVIDER, "LEAVE (A)");

        prev = gLog.called; WOLFPROV_MSG_VERBOSE(WP_LOG_COMP_PROVIDER, "verbose A");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_VERBOSE, WP_LOG_COMP_PROVIDER, "VERBOSE (A)");

        prev = gLog.called; WOLFPROV_MSG_DEBUG(WP_LOG_COMP_PROVIDER, "debug A");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_DEBUG, WP_LOG_COMP_PROVIDER, "DEBUG (A)");

        prev = gLog.called; WOLFPROV_MSG_TRACE(WP_LOG_COMP_PROVIDER, "trace A");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_TRACE, WP_LOG_COMP_PROVIDER, "TRACE (A)");

        {
            static const unsigned char buf[] = { 0x01, 0x02 };
            prev = gLog.called; WOLFPROV_BUFFER(WP_LOG_COMP_PROVIDER, buf, 2);
            CHECK_LOGGED(prev, WP_LOG_LEVEL_VERBOSE, WP_LOG_COMP_PROVIDER, "BUFFER/VERBOSE (A)");
        }
    }

    /* Scenario B: (ERROR | INFO), provider component */
    reset_env_and_init("(WP_LOG_LEVEL_ERROR | WP_LOG_LEVEL_INFO)", "WP_LOG_COMP_PROVIDER");
    {
        int prev;
        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_PROVIDER, "info B");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_PROVIDER, "INFO (B)");

        prev = gLog.called; WOLFPROV_ERROR(WP_LOG_COMP_PROVIDER, -200);
        CHECK_LOGGED(prev, WP_LOG_LEVEL_ERROR, WP_LOG_COMP_PROVIDER, "ERROR (B)");

        prev = gLog.called; WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "funcB");
        CHECK_NOT_LOGGED(prev, WP_LOG_LEVEL_ENTER, WP_LOG_COMP_PROVIDER, "ENTER (B)");

        prev = gLog.called; WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, "funcB", 0);
        CHECK_NOT_LOGGED(prev, WP_LOG_LEVEL_LEAVE, WP_LOG_COMP_PROVIDER, "LEAVE (B)");

        prev = gLog.called; WOLFPROV_MSG_VERBOSE(WP_LOG_COMP_PROVIDER, "verbose B");
        CHECK_NOT_LOGGED(prev, WP_LOG_LEVEL_VERBOSE, WP_LOG_COMP_PROVIDER, "VERBOSE (B)");

        prev = gLog.called; WOLFPROV_MSG_DEBUG(WP_LOG_COMP_PROVIDER, "debug B");
        CHECK_NOT_LOGGED(prev, WP_LOG_LEVEL_DEBUG, WP_LOG_COMP_PROVIDER, "DEBUG (B)");

        prev = gLog.called; WOLFPROV_MSG_TRACE(WP_LOG_COMP_PROVIDER, "trace B");
        CHECK_NOT_LOGGED(prev, WP_LOG_LEVEL_TRACE, WP_LOG_COMP_PROVIDER, "TRACE (B)");
    }

    /* Scenario C: ERROR only */
    reset_env_and_init("WP_LOG_LEVEL_ERROR", "WP_LOG_COMP_PROVIDER");
    {
        int prev;
        prev = gLog.called; WOLFPROV_ERROR(WP_LOG_COMP_PROVIDER, -300);
        CHECK_LOGGED(prev, WP_LOG_LEVEL_ERROR, WP_LOG_COMP_PROVIDER, "ERROR (C)");

        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_PROVIDER, "info C");
        CHECK_NOT_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_PROVIDER, "INFO (C)");
    }

    /* Scenario D: VERBOSE only */
    reset_env_and_init("WP_LOG_LEVEL_VERBOSE", "WP_LOG_COMP_PROVIDER");
    {
        int prev;
        prev = gLog.called; WOLFPROV_MSG_VERBOSE(WP_LOG_COMP_PROVIDER, "verbose D");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_VERBOSE, WP_LOG_COMP_PROVIDER, "VERBOSE (D)");
        /* BUFFER emits VERBOSE */
        {
            static const unsigned char buf[] = { 0xAA, 0xBB };
            prev = gLog.called; WOLFPROV_BUFFER(WP_LOG_COMP_PROVIDER, buf, 2);
            CHECK_LOGGED(prev, WP_LOG_LEVEL_VERBOSE, WP_LOG_COMP_PROVIDER, "BUFFER/VERBOSE (D)");
        }
        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_PROVIDER, "info D");
        CHECK_NOT_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_PROVIDER, "INFO (D)");
    }

    /* Scenario E: ALL levels, RSA component only -> provider logs blocked */
    reset_env_and_init("WP_LOG_LEVEL_ALL", "WP_LOG_COMP_RSA");
    {
        int prev;
        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_PROVIDER, "info E");
        CHECK_NOT_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_PROVIDER, "INFO (E) provider filtered");
        prev = gLog.called; WOLFPROV_ERROR(WP_LOG_COMP_PROVIDER, -400);
        CHECK_NOT_LOGGED(prev, WP_LOG_LEVEL_ERROR, WP_LOG_COMP_PROVIDER, "ERROR (E) provider filtered");

        /* Now log under RSA and expect pass */
        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_RSA, "info E RSA");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_RSA, "INFO (E) RSA");
    }

    /* Scenario H: AES and SHA components with ALL levels */
    reset_env_and_init("WP_LOG_LEVEL_ALL", "(WP_LOG_COMP_AES | WP_LOG_COMP_SHA)");
    {
        int prev;
        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_AES, "info H AES");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_AES, "INFO (H) AES");
        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_SHA, "info H SHA");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_SHA, "INFO (H) SHA");
        /* Provider component should be filtered */
        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_PROVIDER, "info H provider");
        CHECK_NOT_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_PROVIDER, "INFO (H) provider filtered");
    }

    /* Scenario I: RSA component - exercise all log types */
    reset_env_and_init("WP_LOG_LEVEL_ALL", "WP_LOG_COMP_RSA");
    {
        int prev;
        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_RSA, "info I RSA");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_RSA, "INFO (I) RSA");
        prev = gLog.called; WOLFPROV_ERROR(WP_LOG_COMP_RSA, -600);
        CHECK_LOGGED(prev, WP_LOG_LEVEL_ERROR, WP_LOG_COMP_RSA, "ERROR (I) RSA");
        prev = gLog.called; WOLFPROV_ENTER(WP_LOG_COMP_RSA, "funcI");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_ENTER, WP_LOG_COMP_RSA, "ENTER (I) RSA");
        prev = gLog.called; WOLFPROV_LEAVE(WP_LOG_COMP_RSA, "funcI", 0);
        CHECK_LOGGED(prev, WP_LOG_LEVEL_LEAVE, WP_LOG_COMP_RSA, "LEAVE (I) RSA");
        prev = gLog.called; WOLFPROV_MSG_VERBOSE(WP_LOG_COMP_RSA, "verbose I RSA");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_VERBOSE, WP_LOG_COMP_RSA, "VERBOSE (I) RSA");
        prev = gLog.called; WOLFPROV_MSG_DEBUG(WP_LOG_COMP_RSA, "debug I RSA");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_DEBUG, WP_LOG_COMP_RSA, "DEBUG (I) RSA");
        prev = gLog.called; WOLFPROV_MSG_TRACE(WP_LOG_COMP_RSA, "trace I RSA");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_TRACE, WP_LOG_COMP_RSA, "TRACE (I) RSA");
        {
            static const unsigned char buf[] = { 0x10, 0x20 };
            prev = gLog.called; WOLFPROV_BUFFER(WP_LOG_COMP_RSA, buf, 2);
            CHECK_LOGGED(prev, WP_LOG_LEVEL_VERBOSE, WP_LOG_COMP_RSA, "BUFFER/VERBOSE (I) RSA");
        }
    }

    /* Scenario J: AES component - exercise all log types */
    reset_env_and_init("WP_LOG_LEVEL_ALL", "WP_LOG_COMP_AES");
    {
        int prev;
        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_AES, "info J AES");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_AES, "INFO (J) AES");
        prev = gLog.called; WOLFPROV_ERROR(WP_LOG_COMP_AES, -700);
        CHECK_LOGGED(prev, WP_LOG_LEVEL_ERROR, WP_LOG_COMP_AES, "ERROR (J) AES");
        prev = gLog.called; WOLFPROV_ENTER(WP_LOG_COMP_AES, "funcJ");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_ENTER, WP_LOG_COMP_AES, "ENTER (J) AES");
        prev = gLog.called; WOLFPROV_LEAVE(WP_LOG_COMP_AES, "funcJ", 0);
        CHECK_LOGGED(prev, WP_LOG_LEVEL_LEAVE, WP_LOG_COMP_AES, "LEAVE (J) AES");
        prev = gLog.called; WOLFPROV_MSG_VERBOSE(WP_LOG_COMP_AES, "verbose J AES");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_VERBOSE, WP_LOG_COMP_AES, "VERBOSE (J) AES");
        prev = gLog.called; WOLFPROV_MSG_DEBUG(WP_LOG_COMP_AES, "debug J AES");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_DEBUG, WP_LOG_COMP_AES, "DEBUG (J) AES");
        prev = gLog.called; WOLFPROV_MSG_TRACE(WP_LOG_COMP_AES, "trace J AES");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_TRACE, WP_LOG_COMP_AES, "TRACE (J) AES");
        {
            static const unsigned char buf[] = { 0xAB, 0xCD };
            prev = gLog.called; WOLFPROV_BUFFER(WP_LOG_COMP_AES, buf, 2);
            CHECK_LOGGED(prev, WP_LOG_LEVEL_VERBOSE, WP_LOG_COMP_AES, "BUFFER/VERBOSE (J) AES");
        }
    }

    /* Scenario K: SHA component - exercise all log types */
    reset_env_and_init("WP_LOG_LEVEL_ALL", "WP_LOG_COMP_SHA");
    {
        int prev;
        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_SHA, "info K SHA");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_SHA, "INFO (K) SHA");
        prev = gLog.called; WOLFPROV_ERROR(WP_LOG_COMP_SHA, -800);
        CHECK_LOGGED(prev, WP_LOG_LEVEL_ERROR, WP_LOG_COMP_SHA, "ERROR (K) SHA");
        prev = gLog.called; WOLFPROV_ENTER(WP_LOG_COMP_SHA, "funcK");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_ENTER, WP_LOG_COMP_SHA, "ENTER (K) SHA");
        prev = gLog.called; WOLFPROV_LEAVE(WP_LOG_COMP_SHA, "funcK", 0);
        CHECK_LOGGED(prev, WP_LOG_LEVEL_LEAVE, WP_LOG_COMP_SHA, "LEAVE (K) SHA");
        prev = gLog.called; WOLFPROV_MSG_VERBOSE(WP_LOG_COMP_SHA, "verbose K SHA");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_VERBOSE, WP_LOG_COMP_SHA, "VERBOSE (K) SHA");
        prev = gLog.called; WOLFPROV_MSG_DEBUG(WP_LOG_COMP_SHA, "debug K SHA");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_DEBUG, WP_LOG_COMP_SHA, "DEBUG (K) SHA");
        prev = gLog.called; WOLFPROV_MSG_TRACE(WP_LOG_COMP_SHA, "trace K SHA");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_TRACE, WP_LOG_COMP_SHA, "TRACE (K) SHA");
        {
            static const unsigned char buf[] = { 0xDE, 0xAD };
            prev = gLog.called; WOLFPROV_BUFFER(WP_LOG_COMP_SHA, buf, 2);
            CHECK_LOGGED(prev, WP_LOG_LEVEL_VERBOSE, WP_LOG_COMP_SHA, "BUFFER/VERBOSE (K) SHA");
        }
    }

    /* Scenario F: DEFAULT level, ALL components (ERROR | LEAVE | INFO) */
    reset_env_and_init("WP_LOG_LEVEL_DEFAULT", "WP_LOG_COMP_ALL");
    {
        int prev;
        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_PROVIDER, "info F");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_PROVIDER, "INFO (F)");

        prev = gLog.called; WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, "funcF", 0);
        CHECK_LOGGED(prev, WP_LOG_LEVEL_LEAVE, WP_LOG_COMP_PROVIDER, "LEAVE (F)");

        prev = gLog.called; WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "funcF");
        CHECK_NOT_LOGGED(prev, WP_LOG_LEVEL_ENTER, WP_LOG_COMP_PROVIDER, "ENTER (F)");

        prev = gLog.called; WOLFPROV_MSG_VERBOSE(WP_LOG_COMP_PROVIDER, "verbose F");
        CHECK_NOT_LOGGED(prev, WP_LOG_LEVEL_VERBOSE, WP_LOG_COMP_PROVIDER, "VERBOSE (F)");
    }

    /* Scenario G: Mixed valid + invalid tokens -> INFO only */
    reset_env_and_init("(WP_LOG_LEVEL_INFO | WP_LOG_COMP_FAKE)", "WP_LOG_COMP_PROVIDER");
    {
        int prev;
        prev = gLog.called; WOLFPROV_MSG(WP_LOG_COMP_PROVIDER, "info G");
        CHECK_LOGGED(prev, WP_LOG_LEVEL_INFO, WP_LOG_COMP_PROVIDER, "INFO (G)");
        prev = gLog.called; WOLFPROV_ERROR(WP_LOG_COMP_PROVIDER, -500);
        CHECK_NOT_LOGGED(prev, WP_LOG_LEVEL_ERROR, WP_LOG_COMP_PROVIDER, "ERROR (G)");
    }

    /* Cleanup */
    (void)wolfProv_SetLoggingCb(NULL);

    return rc;
#endif /* WOLFPROV_DEBUG */
}

/******************************************************************************/


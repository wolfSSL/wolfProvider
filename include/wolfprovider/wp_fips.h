/* wp_fips.h
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

#ifndef WP_FIPS_H
#define WP_FIPS_H

#ifdef WOLFPROVIDER_USER_SETTINGS
    #include "user_settings.h"
#endif

#include <wolfssl/options.h>

enum wolfProvider_FipsCheck {
    /* check that RSA key size is valid */
    WP_FIPS_CHECK_RSA_KEY_SIZE   = 0x0001,
    /* check that P-192 usage is valid */
    WP_FIPS_CHECK_P192           = 0x0002,
    /* check that RSA signature with SHA-1 digest is valid  */
    WP_FIPS_CHECK_RSA_SHA1       = 0x0004,

    /* default FIPS checks (all with wolfCrypt FIPS, none without) */
#if defined(HAVE_FIPS) || defined(HAVE_FIPS_VERSION)
    WP_FIPS_CHECKS_DEFAULT = (WP_FIPS_CHECK_RSA_KEY_SIZE
                            | WP_FIPS_CHECK_P192
                            | WP_FIPS_CHECK_RSA_SHA1)
#else
    WP_FIPS_CHECKS_DEFAULT = 0
#endif /* HAVE_FIPS || HAVE_FIPS_VERSION */
};

/* Set FIPS checks, bitmask of wolfProvider_FipsCheck. */
void wolfProvider_SetFipsChecks(long checksMask);
/* Get FIPS checks mask. */
long wolfProvider_GetFipsChecks(void);

#endif /* WP_FIPS_H */

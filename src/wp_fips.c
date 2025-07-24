/* wp_fips.c
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

#include <wolfprovider/wp_fips.h>

/* Bitmask of FIPS checks in wolfProvider_FipsCheck. Can be set by application
 * through ENGINE_ctrl command. Defaults to all checks if using wolfCrypt FIPS
 * and no checks if not. */
static long fipsChecks = WP_FIPS_CHECKS_DEFAULT;

/**
 * Set wolfProvider FIPS checks.
 * Default FIPS checks for wolfProvider is WE_FIPS_CHECKS_DEFAULT.
 *
 * @param checksMask  [in]  Bitmask of FIPS checks from wolfProvider_FipsCheck
 *                          in wp_fips.h.
 */
void wolfProvider_SetFipsChecks(long checksMask)
{
    fipsChecks = checksMask;
}

/**
 * Get wolfProvider FIPS checks mask.
 *
 * @return  The FIPS checks mask.
 */
long wolfProvider_GetFipsChecks(void)
{
    return fipsChecks;
}


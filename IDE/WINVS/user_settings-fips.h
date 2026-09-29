/* user_settings-fips.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* What configure supplies for a wolfSSL FIPS build on Linux. Include this at the
 * end of the bundle's IDE\WIN10\user_settings.h -- wolfSSL and wolfProvider must
 * compile against the same one. */

#ifndef WOLFPROV_USER_SETTINGS_FIPS_H
#define WOLFPROV_USER_SETTINGS_FIPS_H

/* --enable-opensslcoexist */
#undef  OPENSSL_EXTRA
#define OPENSSL_COEXIST
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME

/* wolfProvider hardcodes the old OID values. */
#define WOLFSSL_OLD_OID_SUM

/* wc_DhParamsToDer, wc_DhPublicKeyDecode. */
#define WOLFSSL_DH_EXTRA

/* Required for RSA_PSS_SALTLEN_MAX. */
#define WOLFSSL_PSS_LONG_SALT

/* Adds a sign field to struct sp_int -- an ABI change. The bundle derives it
 * from OPENSSL_EXTRA, which the undef above removes. */
#define WOLFSSL_SP_INT_NEGATIVE

#define WOLFSSL_X86_64_BUILD

#endif /* WOLFPROV_USER_SETTINGS_FIPS_H */

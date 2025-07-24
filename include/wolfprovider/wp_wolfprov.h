/* wp_wolfprov.h
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

#include <openssl/provider.h>

#ifndef WP_WOLFPROV_H
#define WP_WOLFPROV_H

extern const char* wolfprovider_id;

int wolfssl_prov_bio_up_ref(OSSL_CORE_BIO *bio);

/* Prototype of public function that initializes the wolfSSL provider. */
OSSL_provider_init_fn wolfssl_provider_init;

#endif /* WP_WOLFPROV_H */

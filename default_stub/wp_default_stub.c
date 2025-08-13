/*
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/* Prototype of public function that initializes the wolfSSL provider. */
OSSL_provider_init_fn wolfssl_provider_init;

/* Prototype for the wolfprov_provider_init function */
int wolfprov_provider_init(const OSSL_CORE_HANDLE* handle,
                          const OSSL_DISPATCH* in,
                          const OSSL_DISPATCH** out,
                          void** provCtx);

/*
 * Provider implementation stub
 */
int wolfprov_provider_init(const OSSL_CORE_HANDLE* handle,
                          const OSSL_DISPATCH* in,
                          const OSSL_DISPATCH** out,
                          void** provCtx)
{
    return 0;
}

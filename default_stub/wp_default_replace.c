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

/*
 * wolfProvider Real Implementation for libdefault.so
 *
 * This is the real implementation of wolfprov_provider_init that bridges
 * OpenSSL's default provider interface to wolfProvider by dynamically
 * loading libwolfprov.so and calling wolfssl_provider_init.
 *
 * This replaces the stub implementation after wolfProvider is fully built.
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
 * Real implementation of wolfprov_provider_init.
 *
 * This function dynamically loads libwolfprov.so and calls its
 * wolfssl_provider_init function to provide full wolfProvider functionality.
 *
 * @param [in]  handle   Handle to the core.
 * @param [in]  in       Dispatch table from previous provider.
 * @param [out] out      Dispatch table of wolfSSL provider.
 * @param [out] provCtx  New provider context.
 * @return  1 on success, 0 on failure.
 */
int wolfprov_provider_init(const OSSL_CORE_HANDLE* handle,
                          const OSSL_DISPATCH* in,
                          const OSSL_DISPATCH** out,
                          void** provCtx)
{
    return wolfssl_provider_init(handle, in, out, provCtx);
}

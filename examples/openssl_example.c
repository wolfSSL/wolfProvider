/* openssl_example.c
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

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#define WOLFPROV_NAME "libwolfprov"

int main(int argc, char** argv)
{
    int rc = 0;
    const char* buildInfo = NULL;
    OSSL_LIB_CTX* libCtx = NULL;
    OSSL_PROVIDER* wolfProv = NULL;
    OSSL_PARAM request[] = {
        OSSL_PARAM_utf8_ptr("buildinfo", (char**)&buildInfo, 0),
        OSSL_PARAM_END
    };
    char executable[PATH_MAX];
    char providerPath[PATH_MAX];

    libCtx = OSSL_LIB_CTX_new();
    if (libCtx == NULL) {
        rc = 1;
    }

    if (rc == 0) {
        if ((argc < 1) || (realpath(argv[0], executable) == NULL) ||
                (snprintf(providerPath, sizeof(providerPath), "%s/../.libs",
                    executable) >= (int)sizeof(providerPath))) {
            rc = 1;
        }
    }
    if (rc == 0) {
        OSSL_PROVIDER_set_default_search_path(libCtx, providerPath);
        wolfProv = OSSL_PROVIDER_load(libCtx, WOLFPROV_NAME);
        if ((wolfProv == NULL) ||
                (OSSL_PROVIDER_get_params(wolfProv, request) != 1)) {
            rc = 1;
        }
    }

    if (rc == 0) {
        printf("Provider '%s' buildinfo: %s\n", WOLFPROV_NAME, buildInfo);
        if (OSSL_PROVIDER_self_test(wolfProv) != 1) {
            fprintf(stderr, "Provider self-test failed\n");
            rc = 1;
        }
    }
    if (rc == 0) {
        printf("Provider self-test passed\n");
    }

    if (rc != 0) {
        ERR_print_errors_fp(stderr);
    }
    OSSL_PROVIDER_unload(wolfProv);
    OSSL_LIB_CTX_free(libCtx);
    return rc;
}

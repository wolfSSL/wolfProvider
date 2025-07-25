/* test_rand.c
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

#include "unit.h"

#ifdef WP_HAVE_RANDOM

static int test_random_api(void)
{
    int err;
    unsigned char buf[128];

    err = RAND_status() != 1;
    if (err == 0) {
        err = RAND_priv_bytes(buf, sizeof(buf)) != 1;
        PRINT_BUFFER("True random", buf, sizeof(buf));
    }
    if (err == 0) {
        RAND_seed(buf, sizeof(buf));

        RAND_add(buf, sizeof(buf), 128);

        err = RAND_bytes(buf, sizeof(buf)) != 1;
        PRINT_BUFFER("Seeded", buf, sizeof(buf));
    }
    if (err == 0) {
        err = RAND_status() != 1;
    }

    return err;
}

int test_random(void *data)
{
    int err;
    OSSL_LIB_CTX* origLibCtx;

    (void)data;

    PRINT_MSG("Set OpenSSL as default library context");
    origLibCtx = OSSL_LIB_CTX_set0_default(osslLibCtx);
    err = test_random_api();
    if (err == 0) {
        PRINT_MSG("Set wolfProvider as default library context");
        OSSL_LIB_CTX_set0_default(wpLibCtx);
        err = test_random_api();
    }
    OSSL_LIB_CTX_set0_default(origLibCtx);

    return err;
}

#endif /* WP_HAVE_RANDOM */

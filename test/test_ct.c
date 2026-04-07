/* test_ct.c
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
#include "unit.h"

int test_ct_masks(void *data)
{
    int err = 0;
    int a, b;
    byte res;

    (void)data;

    PRINT_MSG("Testing CT byte mask functions (exhaustive)");

    /* Exhaustive test of all 65536 byte pairs for eq, ne, and their
     * relationship: ne(a,b) == (byte)~eq(a,b). */
    for (a = 0; a <= 255 && err == 0; a++) {
        for (b = 0; b <= 255 && err == 0; b++) {
            byte eqRes = wp_ct_byte_mask_eq((byte)a, (byte)b);
            byte neRes = wp_ct_byte_mask_ne((byte)a, (byte)b);
            byte expEq = (a == b) ? 0xFF : 0x00;
            byte expNe = (a != b) ? 0xFF : 0x00;
            byte eqNeg;

            if (eqRes != expEq) {
                PRINT_ERR_MSG("ct_byte_mask_eq(%d, %d) = 0x%02x, expected "
                              "0x%02x", a, b, eqRes, expEq);
                err = 1;
            }
            if (neRes != expNe) {
                PRINT_ERR_MSG("ct_byte_mask_ne(%d, %d) = 0x%02x, expected "
                              "0x%02x", a, b, neRes, expNe);
                err = 1;
            }
            eqNeg = (byte)(eqRes ^ (byte)0xFF);
            if (eqNeg != neRes) {
                PRINT_ERR_MSG("ct_byte_mask ne/eq mismatch at (%d, %d): "
                              "~eq=0x%02x ne=0x%02x", a, b,
                              eqNeg, neRes);
                err = 1;
            }
        }
    }

    PRINT_MSG("Testing CT int mask functions (boundary values)");

    /* Test int comparison functions over a set of boundary values that cover
     * the actual usage domain (padding indices, record lengths, versions). */
    {
        static const int vals[] = {0, 1, 2, 127, 128, 254, 255, 256, 1000};
        int nvals = (int)(sizeof(vals) / sizeof(vals[0]));
        int i, j;

        for (i = 0; i < nvals && err == 0; i++) {
            for (j = 0; j < nvals && err == 0; j++) {
                a = vals[i];
                b = vals[j];

                res = wp_ct_int_mask_gte(a, b);
                if (res != ((a >= b) ? 0xFF : 0x00)) {
                    PRINT_ERR_MSG("ct_int_mask_gte(%d, %d) = 0x%02x, expected "
                                  "0x%02x", a, b, res,
                                  (a >= b) ? 0xFF : 0x00);
                    err = 1;
                }

                res = wp_ct_int_mask_eq(a, b);
                if (res != ((a == b) ? 0xFF : 0x00)) {
                    PRINT_ERR_MSG("ct_int_mask_eq(%d, %d) = 0x%02x, expected "
                                  "0x%02x", a, b, res,
                                  (a == b) ? 0xFF : 0x00);
                    err = 1;
                }

                res = wp_ct_int_mask_lt(a, b);
                if (res != ((a < b) ? 0xFF : 0x00)) {
                    PRINT_ERR_MSG("ct_int_mask_lt(%d, %d) = 0x%02x, expected "
                                  "0x%02x", a, b, res,
                                  (a < b) ? 0xFF : 0x00);
                    err = 1;
                }
            }
        }
    }

    PRINT_MSG("Testing CT byte mask sel");

    /* Selection: mask=0xFF picks a, mask=0x00 picks b. */
    res = wp_ct_byte_mask_sel(0xFF, 0xAB, 0xCD);
    if (res != 0xAB) {
        PRINT_ERR_MSG("ct_byte_mask_sel(0xFF, 0xAB, 0xCD) = 0x%02x", res);
        err = 1;
    }
    res = wp_ct_byte_mask_sel(0x00, 0xAB, 0xCD);
    if (res != 0xCD) {
        PRINT_ERR_MSG("ct_byte_mask_sel(0x00, 0xAB, 0xCD) = 0x%02x", res);
        err = 1;
    }

    /* Selection driven by eq/ne masks. */
    res = wp_ct_byte_mask_sel(wp_ct_byte_mask_eq(5, 5), 0x11, 0x22);
    if (res != 0x11) {
        PRINT_ERR_MSG("ct_byte_mask_sel(eq(5,5), 0x11, 0x22) = 0x%02x", res);
        err = 1;
    }
    res = wp_ct_byte_mask_sel(wp_ct_byte_mask_eq(5, 6), 0x11, 0x22);
    if (res != 0x22) {
        PRINT_ERR_MSG("ct_byte_mask_sel(eq(5,6), 0x11, 0x22) = 0x%02x", res);
        err = 1;
    }

    return err;
}

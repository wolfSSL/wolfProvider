/* test_dh.c
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
#include <openssl/core_names.h>
#include <openssl/decoder.h>

#ifdef WP_HAVE_DH

/* dh pkcs8 private key der */
static const unsigned char dh_der[] = {
    0x30, 0x82, 0x02, 0x26, 0x02, 0x01, 0x00, 0x30, 0x82, 0x01, 0x17, 0x06,
    0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x03, 0x01, 0x30, 0x82,
    0x01, 0x08, 0x02, 0x82, 0x01, 0x01, 0x00, 0xBA, 0x58, 0x07, 0x7D, 0xB2,
    0x45, 0x41, 0x40, 0xF7, 0x72, 0xDF, 0x98, 0x98, 0x51, 0x7D, 0xBE, 0x17,
    0xE3, 0xD0, 0xB6, 0xCA, 0x38, 0xC3, 0x65, 0x7F, 0xE2, 0x13, 0xC1, 0x42,
    0x1A, 0x7A, 0x94, 0x2B, 0xB5, 0x58, 0xC0, 0x39, 0xD4, 0xB8, 0x41, 0xFD,
    0x21, 0xCF, 0xE3, 0x9C, 0x17, 0xB9, 0x8D, 0x34, 0x1A, 0x98, 0x81, 0xAF,
    0xAE, 0x19, 0xD5, 0x01, 0x9F, 0xD3, 0x29, 0xD1, 0x29, 0xEF, 0xDD, 0x73,
    0x4B, 0xF4, 0xEB, 0x87, 0xAC, 0xF3, 0xF9, 0xBD, 0x8B, 0xD5, 0xAD, 0x20,
    0xE4, 0xEB, 0x6C, 0x99, 0xDE, 0x40, 0x76, 0xF3, 0x18, 0x41, 0x85, 0xE9,
    0x1D, 0xFE, 0x8C, 0xEA, 0x5B, 0xAD, 0xB4, 0x11, 0xCA, 0x0D, 0x22, 0x0C,
    0xD7, 0x06, 0xAD, 0x06, 0x59, 0xFB, 0x1B, 0x61, 0xEB, 0xF4, 0x1B, 0xCA,
    0x6E, 0x8C, 0x0F, 0x92, 0x8D, 0xF3, 0x80, 0x1B, 0x4A, 0xAF, 0xF2, 0x9E,
    0x3F, 0x60, 0xFD, 0xB1, 0x49, 0x6D, 0xCA, 0x0B, 0xD4, 0x99, 0x3B, 0x45,
    0xA5, 0xB1, 0xED, 0xA1, 0xB7, 0x94, 0xD0, 0x33, 0xA5, 0x21, 0xEB, 0x29,
    0xC2, 0xEB, 0xFB, 0x5C, 0x1A, 0xD5, 0xAF, 0xC4, 0xC9, 0x02, 0xCD, 0x7A,
    0xEB, 0xB4, 0xC5, 0x7B, 0x34, 0xBD, 0x2F, 0x4F, 0xA0, 0xC4, 0x63, 0x6A,
    0xFE, 0x98, 0xD0, 0x83, 0xFA, 0xEF, 0x6F, 0xAF, 0xA8, 0x4B, 0x46, 0x59,
    0x77, 0xCA, 0xC5, 0x19, 0xDA, 0x8A, 0x77, 0xC6, 0x56, 0x08, 0xD6, 0x0A,
    0xAD, 0xFC, 0x04, 0x35, 0xFA, 0xDA, 0xAA, 0x08, 0x42, 0x1B, 0x48, 0xE8,
    0x42, 0x3C, 0x4F, 0x31, 0xA2, 0x22, 0xE9, 0xF3, 0x0F, 0xD7, 0x06, 0xCB,
    0x08, 0x54, 0x7C, 0x2C, 0xEA, 0x38, 0x11, 0x2B, 0x53, 0x7C, 0xE5, 0x86,
    0xC9, 0x74, 0xB9, 0x98, 0x68, 0x6D, 0xE4, 0xF0, 0x7A, 0x2B, 0xE5, 0xB9,
    0x4E, 0xAD, 0xD1, 0x34, 0xC7, 0x4C, 0xFE, 0x1A, 0x7C, 0x8A, 0x37, 0x02,
    0x01, 0x02, 0x04, 0x82, 0x01, 0x04, 0x02, 0x82, 0x01, 0x00, 0x45, 0xED,
    0x6E, 0x18, 0x44, 0x8F, 0xA0, 0x43, 0x04, 0xF7, 0xE0, 0x5E, 0x98, 0x23,
    0xFB, 0xE8, 0xDA, 0x49, 0x7E, 0x2A, 0x11, 0xEC, 0xD0, 0xCD, 0xB7, 0x13,
    0xE1, 0x11, 0xCB, 0xDA, 0x00, 0x34, 0x13, 0x16, 0x5A, 0xB5, 0xEA, 0x2D,
    0xCC, 0xAB, 0x0D, 0xE1, 0x75, 0x5D, 0xCA, 0xBC, 0x1E, 0xBD, 0x5D, 0x01,
    0xB4, 0xC3, 0xCA, 0x78, 0xDF, 0x4C, 0x4F, 0x1B, 0x21, 0x40, 0x8A, 0x64,
    0x7F, 0x4B, 0x45, 0xE3, 0x7F, 0x43, 0xD7, 0xFD, 0x4E, 0xA0, 0xA1, 0x4A,
    0x1C, 0x5A, 0x8D, 0x87, 0x7E, 0x5A, 0xB5, 0x26, 0x1A, 0xDC, 0x9B, 0xDD,
    0xD1, 0x8D, 0xD0, 0xBB, 0x45, 0x0F, 0x67, 0x41, 0xC1, 0xC0, 0xA5, 0x7B,
    0x6A, 0x35, 0x51, 0x06, 0x14, 0xC7, 0x61, 0x0D, 0xF7, 0x01, 0x30, 0x0A,
    0xB5, 0x07, 0xF6, 0x8F, 0x76, 0xCF, 0x99, 0x1F, 0xAF, 0x2C, 0x66, 0x20,
    0xB4, 0x69, 0x0A, 0xC3, 0x04, 0x76, 0x1B, 0xF4, 0x0D, 0x7C, 0x54, 0x0A,
    0xB8, 0xF6, 0xF8, 0x35, 0x17, 0x81, 0xDD, 0x6E, 0xCE, 0x17, 0xBD, 0x00,
    0x9C, 0x5D, 0x3F, 0x37, 0x37, 0xC4, 0x58, 0xBC, 0xA5, 0xB3, 0xD3, 0x0F,
    0x98, 0x0F, 0x6C, 0x0C, 0x78, 0x53, 0x92, 0x36, 0x94, 0x4D, 0xF5, 0x7D,
    0x1A, 0xD8, 0xC6, 0x54, 0x0A, 0xED, 0x79, 0xAA, 0xAC, 0x4F, 0xFF, 0x2B,
    0x41, 0xC6, 0x41, 0x7A, 0x4D, 0xBC, 0xB0, 0x43, 0xF9, 0x22, 0x33, 0xD4,
    0xAA, 0x43, 0x75, 0xAD, 0x97, 0xAB, 0xE8, 0xCC, 0x57, 0xFA, 0x0D, 0x48,
    0x08, 0x44, 0x99, 0x6A, 0x9D, 0x14, 0x14, 0x4D, 0x32, 0x00, 0x3E, 0x8A,
    0x82, 0x30, 0xB1, 0x85, 0x3E, 0xD2, 0xD3, 0x8C, 0xEF, 0x73, 0x72, 0x56,
    0x28, 0xF5, 0xBA, 0x2F, 0x85, 0x45, 0x46, 0xD1, 0xED, 0x42, 0x2E, 0x9A,
    0xAE, 0x4F, 0x41, 0x5B, 0xBD, 0x9C, 0xF9, 0x58, 0x8D, 0xFA, 0x13, 0xB4,
    0xDF, 0x31,
};


/* Random 2048-bit DH prime (not a named group) */
static const unsigned char dh_p[] = {
    0xc4, 0xa9, 0x96, 0x01, 0x1d, 0xe9, 0x31, 0xd3,
    0x76, 0xdc, 0xae, 0xda, 0x11, 0x68, 0xee, 0xae,
    0x5f, 0x3e, 0x8f, 0x78, 0x36, 0x13, 0xfc, 0x91,
    0xba, 0x74, 0x7f, 0xdb, 0xd7, 0x04, 0x13, 0x50,
    0xee, 0xba, 0xa8, 0xa3, 0xca, 0xe5, 0x26, 0xa4,
    0x78, 0x60, 0xb9, 0xa3, 0xc0, 0xad, 0x14, 0x30,
    0xd9, 0xe5, 0x6a, 0xa3, 0xe2, 0xf2, 0xe5, 0xc8,
    0x08, 0xcd, 0x7b, 0x93, 0x8d, 0xbe, 0xe0, 0x6c,
    0x0f, 0x34, 0x90, 0xd8, 0x30, 0x06, 0x22, 0xad,
    0xfc, 0x43, 0x40, 0xd6, 0xbd, 0x51, 0x21, 0x2f,
    0x15, 0x09, 0x85, 0xa3, 0x70, 0xcc, 0x35, 0x49,
    0xea, 0x79, 0x08, 0x22, 0xdb, 0x94, 0x0b, 0xf8,
    0x40, 0x1c, 0xcb, 0x64, 0x9c, 0x20, 0x95, 0xff,
    0xc6, 0xb9, 0x03, 0x24, 0x80, 0x55, 0x28, 0xe1,
    0x08, 0x0a, 0x24, 0xd2, 0xfc, 0xc6, 0xe7, 0xbd,
    0xd9, 0x17, 0x04, 0x0c, 0x57, 0x20, 0x65, 0x6f,
    0xf7, 0x8b, 0x1c, 0x93, 0x3a, 0xc0, 0x32, 0xe6,
    0x4f, 0x63, 0xaf, 0xe1, 0xbf, 0xb8, 0xe7, 0x5f,
    0xe6, 0x0e, 0x5f, 0x9e, 0xf3, 0x45, 0x8f, 0xbf,
    0x9e, 0xe6, 0xd8, 0x0d, 0xa0, 0x0c, 0x81, 0xa8,
    0x3f, 0xfc, 0x07, 0xf3, 0x21, 0xe1, 0xdd, 0x73,
    0x9f, 0x23, 0xfd, 0x49, 0xcd, 0xa0, 0x1d, 0x0f,
    0xbe, 0xed, 0xb5, 0x7f, 0x07, 0x7b, 0x67, 0x7c,
    0xd7, 0xd3, 0xd5, 0xc2, 0x22, 0x8b, 0x24, 0x62,
    0xe1, 0xa4, 0x84, 0x18, 0xda, 0xac, 0xca, 0xd2,
    0xdc, 0x17, 0x37, 0xb2, 0x8a, 0x20, 0x5b, 0x52,
    0x18, 0xe5, 0xd2, 0xaa, 0x91, 0x3e, 0x23, 0x9b,
    0x4e, 0xe3, 0xfc, 0xa5, 0xfc, 0x0f, 0x99, 0xae,
    0xa7, 0x90, 0xdb, 0x66, 0x68, 0x18, 0xcd, 0xd6,
    0xd3, 0xfc, 0x10, 0x73, 0x9b, 0x44, 0xb3, 0x55,
    0xa5, 0x58, 0xfc, 0xff, 0x7a, 0xc1, 0x01, 0xac,
    0xe0, 0xf8, 0x8d, 0xd6, 0x8c, 0x10, 0x1d, 0x67
};

/* dh2048 g */
static const unsigned char dh_g[] = {
    0x02
};

/* Fixed param from krb5 DH generation, named "o2048" */
static const uint8_t dh_2048[] = {
    0x30, 0x82, 0x02, 0x0C, 0x02, 0x82, 0x01, 0x01,
    0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2,
    0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C,
    0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC,
    0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B,
    0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04,
    0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43,
    0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14,
    0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2,
    0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E,
    0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED,
    0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7,
    0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F,
    0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F,
    0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B,
    0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF,
    0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3,
    0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF,
    0x5F, 0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD,
    0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52,
    0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96,
    0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98,
    0x04, 0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21,
    0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE,
    0x3B, 0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86,
    0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2,
    0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52,
    0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17,
    0x18, 0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A,
    0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05,
    0x10, 0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA,
    0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x02, 0x01, 0x02, 0x02, 0x82, 0x01, 0x00,
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xE4, 0x87, 0xED, 0x51, 0x10, 0xB4, 0x61, 0x1A,
    0x62, 0x63, 0x31, 0x45, 0xC0, 0x6E, 0x0E, 0x68,
    0x94, 0x81, 0x27, 0x04, 0x45, 0x33, 0xE6, 0x3A,
    0x01, 0x05, 0xDF, 0x53, 0x1D, 0x89, 0xCD, 0x91,
    0x28, 0xA5, 0x04, 0x3C, 0xC7, 0x1A, 0x02, 0x6E,
    0xF7, 0xCA, 0x8C, 0xD9, 0xE6, 0x9D, 0x21, 0x8D,
    0x98, 0x15, 0x85, 0x36, 0xF9, 0x2F, 0x8A, 0x1B,
    0xA7, 0xF0, 0x9A, 0xB6, 0xB6, 0xA8, 0xE1, 0x22,
    0xF2, 0x42, 0xDA, 0xBB, 0x31, 0x2F, 0x3F, 0x63,
    0x7A, 0x26, 0x21, 0x74, 0xD3, 0x1B, 0xF6, 0xB5,
    0x85, 0xFF, 0xAE, 0x5B, 0x7A, 0x03, 0x5B, 0xF6,
    0xF7, 0x1C, 0x35, 0xFD, 0xAD, 0x44, 0xCF, 0xD2,
    0xD7, 0x4F, 0x92, 0x08, 0xBE, 0x25, 0x8F, 0xF3,
    0x24, 0x94, 0x33, 0x28, 0xF6, 0x72, 0x2D, 0x9E,
    0xE1, 0x00, 0x3E, 0x5C, 0x50, 0xB1, 0xDF, 0x82,
    0xCC, 0x6D, 0x24, 0x1B, 0x0E, 0x2A, 0xE9, 0xCD,
    0x34, 0x8B, 0x1F, 0xD4, 0x7E, 0x92, 0x67, 0xAF,
    0xC1, 0xB2, 0xAE, 0x91, 0xEE, 0x51, 0xD6, 0xCB,
    0x0E, 0x31, 0x79, 0xAB, 0x10, 0x42, 0xA9, 0x5D,
    0xCF, 0x6A, 0x94, 0x83, 0xB8, 0x4B, 0x4B, 0x36,
    0xB3, 0x86, 0x1A, 0xA7, 0x25, 0x5E, 0x4C, 0x02,
    0x78, 0xBA, 0x36, 0x04, 0x65, 0x0C, 0x10, 0xBE,
    0x19, 0x48, 0x2F, 0x23, 0x17, 0x1B, 0x67, 0x1D,
    0xF1, 0xCF, 0x3B, 0x96, 0x0C, 0x07, 0x43, 0x01,
    0xCD, 0x93, 0xC1, 0xD1, 0x76, 0x03, 0xD1, 0x47,
    0xDA, 0xE2, 0xAE, 0xF8, 0x37, 0xA6, 0x29, 0x64,
    0xEF, 0x15, 0xE5, 0xFB, 0x4A, 0xAC, 0x0B, 0x8C,
    0x1C, 0xCA, 0xA4, 0xBE, 0x75, 0x4A, 0xB5, 0x72,
    0x8A, 0xE9, 0x13, 0x0C, 0x4C, 0x7D, 0x02, 0x88,
    0x0A, 0xB9, 0x47, 0x2D, 0x45, 0x56, 0x55, 0x34,
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static int test_dh_pkey_keygen(EVP_PKEY *params)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *keyOpenSSL = NULL;
    EVP_PKEY *keyWolfProvider = NULL;
    unsigned char *secretOpenSSL = NULL;
    size_t secretLenOpenSSL = 0;
    unsigned char *secretWolfProvider = NULL;
    size_t secretLenWolfProvider = 0;

    PRINT_MSG("Generate DH key pair with WolfSSL and params from "
              "wolfProvider");
    ctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, params, NULL);
    err = ctx == NULL;
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctx, &keyWolfProvider) != 1;
    }

    if (err == 0) {
        PRINT_MSG("Generate DH key pair with OpenSSL and params from "
                  "wolfProvider");
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_pkey(osslLibCtx, params, NULL);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctx, &keyOpenSSL) != 1;
    }

    if (err == 0) {
        PRINT_MSG("Compute shared secret with OpenSSL private key and "
                  "wolfProvider public key.");
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_pkey(osslLibCtx, keyOpenSSL, NULL);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_set_peer(ctx, keyWolfProvider) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, NULL, &secretLenOpenSSL) <= 0;
    }
    if (err == 0) {
        secretOpenSSL = (unsigned char*)OPENSSL_malloc(secretLenOpenSSL);
        err = secretOpenSSL == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, secretOpenSSL, &secretLenOpenSSL) <= 0;
    }

    if (err == 0) {
        PRINT_BUFFER("Secret", secretOpenSSL, secretLenOpenSSL);
        PRINT_MSG("Compute shared secret with wolfProvider private key and "
                  "OpenSSL public key.");
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, keyWolfProvider, NULL);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_set_peer(ctx, keyOpenSSL) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, NULL, &secretLenWolfProvider) <= 0;
    }
    if (err == 0) {
        secretWolfProvider = (unsigned char*)OPENSSL_malloc(secretLenWolfProvider);
        err = secretWolfProvider == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, secretWolfProvider, &secretLenWolfProvider) <= 0;
    }

    if (err == 0) {
        PRINT_BUFFER("Secret", secretOpenSSL, secretLenOpenSSL);
        PRINT_MSG("Ensure shared secrets are the same.");
        err = secretLenOpenSSL != secretLenWolfProvider;
    }
    if (err == 0) {
        err = memcmp(secretOpenSSL, secretWolfProvider, secretLenOpenSSL) != 0;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(keyOpenSSL);
    EVP_PKEY_free(keyWolfProvider);

    if (secretWolfProvider != NULL)
        OPENSSL_free(secretWolfProvider);
    if (secretOpenSSL != NULL)
        OPENSSL_free(secretOpenSSL);

    return err;
}

int test_dh_pgen_pkey(void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *params = NULL;

    (void)data;

    PRINT_MSG("Generate DH parameters and key pair with wolfProvider");
    err = (ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, "DH", NULL)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_paramgen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen(ctx, &params) != 1;
    }

    if (err == 0) {
        err = test_dh_pkey_keygen(params);
    }

    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

int test_dh_pkey(void *data)
{
    int err;
    DH *dh;
    EVP_PKEY *params = NULL;
    BIGNUM *p;
    BIGNUM *g;

    (void)data;

    dh = DH_new();
    err = (dh == NULL);
    if (err == 0) {
        p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
        err = p == NULL;
    }
    if (err == 0) {
        g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
        err = g == NULL;
    }
    if (err == 0) {
        err = DH_set0_pqg(dh, p, NULL, g) == 0;
    }
    if (err == 0) {
        err = (params = EVP_PKEY_new()) == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_set1_DH(params, dh) != 1;
    }

    if (err == 0) {
        err = test_dh_pkey_keygen(params);
    }

    EVP_PKEY_free(params);
    DH_free(dh);

    return err;
}

int test_dh_invalid_kdf_strings(void *data)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    const unsigned char *p = dh_der;
    char *invalidKdfs[] = {
        (char *)"X",
        (char *)"X942",
        (char *)"X942KDF",
        (char *)"X942KDF-AS"
    };
    size_t i;

    (void)data;

    PRINT_MSG("Reject invalid DH KDF type strings");

    key = d2i_PrivateKey_ex(EVP_PKEY_DH, NULL, &p, sizeof(dh_der), wpLibCtx,
        NULL);
    err = key == NULL;
    if (err == 0) {
        ctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key, NULL);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) != 1;
    }
    for (i = 0; (err == 0) && (i < (sizeof(invalidKdfs) / sizeof(*invalidKdfs)));
            i++) {
        OSSL_PARAM params[2];

        params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_EXCHANGE_PARAM_KDF_TYPE, invalidKdfs[i], 0);
        params[1] = OSSL_PARAM_construct_end();

        err = EVP_PKEY_CTX_set_params(ctx, params) > 0;
        if (err != 0) {
            PRINT_ERR_MSG("Accepted invalid DH KDF type: %s", invalidKdfs[i]);
        }
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    return err;
}

int test_dh_decode(void *data)
{
    int err = 0;
    const unsigned char *p = NULL;
    int len = 0;
    PKCS8_PRIV_KEY_INFO* p8inf = NULL;
    EVP_PKEY* pkey1 = NULL;
    DH *dh1 = NULL;
    const BIGNUM *p1 = NULL;
    const BIGNUM *g1 = NULL;
    const BIGNUM *priv1 = NULL;
    const BIGNUM *pub1 = NULL;
    EVP_PKEY* pkey2 = NULL;
    DH *dh2 = NULL;
    const BIGNUM *p2 = NULL;
    const BIGNUM *g2 = NULL;
    const BIGNUM *priv2 = NULL;
    const BIGNUM *pub2 = NULL;

    (void)data;

    p = &dh_der[0];
    len = sizeof(dh_der);
    p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, (const unsigned char **)&p, len);
    err = p8inf == NULL;

    if (err == 0) {
        PRINT_MSG("Decode with OpenSSL and Wolfprovider");
        pkey1 = EVP_PKCS82PKEY_ex(p8inf, osslLibCtx, NULL);
        pkey2 = EVP_PKCS82PKEY_ex(p8inf, wpLibCtx, NULL);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        err = (pkey1 == NULL || pkey2 == NULL);
    }

    if (err == 0) {
        dh1 = EVP_PKEY_get1_DH(pkey1);
        dh2 = EVP_PKEY_get1_DH(pkey2);
        err = (dh1 == NULL || dh2 == NULL);
    }

    if (err == 0) {
        DH_get0_pqg(dh1, &p1, NULL, &g1);
        err = (p1 == NULL || g1 == NULL);
    }
    if (err == 0) {
        DH_get0_pqg(dh2, &p2, NULL, &g2);
        err = (p2 == NULL || g2 == NULL);
    }

    if (err == 0) {
        DH_get0_key(dh1, &pub1, &priv1);
        err = (pub1 == NULL || priv1 == NULL);
    }
    if (err == 0) {
        DH_get0_key(dh2, &pub2, &priv2);
        err = (pub2 == NULL || priv2 == NULL);
    }

    if (err == 0) {
        err = BN_cmp(p1, p2) != 0;
    }
    if (err == 0) {
        err = BN_cmp(g1, g2) != 0;
    }
    if (err == 0) {
        err = BN_cmp(priv1, priv2) != 0;
    }
    if (err == 0) {
        err = BN_cmp(pub1, pub2) != 0;
    }

    DH_free(dh1);
    DH_free(dh2);
    EVP_PKEY_free(pkey1);
    EVP_PKEY_free(pkey2);

    return err;
}

int test_dh_get_params(void *data) 
{
    (void)data;
    int err = 0;
    EVP_PKEY_CTX *ctxOpenSSL = NULL;
    EVP_PKEY_CTX *ctxWolfProvider = NULL;
    EVP_PKEY *keyParamsOpenSSL = NULL;
    EVP_PKEY *keyParamsWolfProvider = NULL;
    EVP_PKEY *keyOpenSSL = NULL;
    EVP_PKEY *keyWolfProvider = NULL;

    if (err == 0) {
        ctxOpenSSL = EVP_PKEY_CTX_new_from_name(osslLibCtx, "DH", NULL);
        err = ctxOpenSSL == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen_init(ctxOpenSSL) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctxOpenSSL, 2048) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen(ctxOpenSSL, &keyParamsOpenSSL) != 1;
    }
    if (err == 0) {
        EVP_PKEY_CTX_free(ctxOpenSSL);
        ctxOpenSSL = EVP_PKEY_CTX_new_from_pkey(osslLibCtx, keyParamsOpenSSL, NULL);
        err = ctxOpenSSL == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctxOpenSSL) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctxOpenSSL, &keyOpenSSL) != 1;
    }

    if (err == 0) {
        ctxWolfProvider = EVP_PKEY_CTX_new_from_name(wpLibCtx, "DH", NULL);
        err = ctxWolfProvider == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen_init(ctxWolfProvider) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctxWolfProvider, 2048) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen(ctxWolfProvider, &keyParamsWolfProvider) != 1;
    }
    if (err == 0) {
        EVP_PKEY_CTX_free(ctxWolfProvider);
        ctxWolfProvider = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, keyParamsWolfProvider, NULL);
        err = ctxWolfProvider == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctxWolfProvider) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctxWolfProvider, &keyWolfProvider) != 1;
    }

    static const OSSL_PARAM gettableParams[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        /* Note that OpenSSL treats the keys as BIGNUMs, not strings. */
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END
    };
    // const size_t paramsSize = sizeof(gettableParams);

    if (err == 0) {
        int retWolfProvider;
        unsigned char bufWolfProvider[256];
        const char* mode;

        OSSL_PARAM paramsWolfProvider[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

        for (int i = 0; i < (int)(sizeof(gettableParams)/sizeof(gettableParams[0])) - 1; i++) {
            memset(bufWolfProvider, 0, sizeof(bufWolfProvider));
            for (int j = 0; j < 2; j++) {
                if (j == 0) {
                    mode = "Null data";
                    paramsWolfProvider[0] = gettableParams[i];
                    paramsWolfProvider[0].data = NULL;
                    paramsWolfProvider[0].data_size = 0;
                }
                else {
                    mode = "Buffer data";
                    paramsWolfProvider[0] = gettableParams[i];
                    paramsWolfProvider[0].data = bufWolfProvider;
                    paramsWolfProvider[0].data_size = sizeof(bufWolfProvider);
                }

                retWolfProvider = EVP_PKEY_get_params(keyWolfProvider, paramsWolfProvider);
                if (retWolfProvider != 1) {
                    PRINT_MSG("EVP_PKEY_get_params failed for param %s in mode %s (WolfProvider (%d))",
                            gettableParams[i].key, mode, retWolfProvider);
                    err = 1;
                }
                if (err == 0 && paramsWolfProvider[0].data) {
                    if (paramsWolfProvider[0].return_size == 0) {
                        PRINT_MSG("EVP_PKEY_get_params did not set return_size for param %s in mode %s (WolfProvider (%d))",
                                gettableParams[i].key, mode, retWolfProvider);
                        err = 1;
                    }
                }
            }
        }
    }

    EVP_PKEY_CTX_free(ctxOpenSSL);
    EVP_PKEY_CTX_free(ctxWolfProvider);
    EVP_PKEY_free(keyOpenSSL);
    EVP_PKEY_free(keyWolfProvider);
    EVP_PKEY_free(keyParamsOpenSSL);
    EVP_PKEY_free(keyParamsWolfProvider);

    return err;
}

static int test_dh_krb5_keygen_ex(OSSL_LIB_CTX *libCtx)
{
    int err = 0;
    EVP_PKEY *params = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    const unsigned char *inptr = dh_2048;
    size_t inlen = sizeof(dh_2048);
#ifdef WOLFSSL_DH_EXTRA
    unsigned char *spki = NULL;
    size_t spki_len = 0;
    unsigned char *der = NULL;
    size_t der_len;
#endif /* WOLFSSL_DH_EXTRA */

    PRINT_MSG("Testing DH key generation with krb5 parameters");

    /* Create decoder context for DH parameters */
    dctx = OSSL_DECODER_CTX_new_for_pkey(&params, "DER", "type-specific", "DHX",
        EVP_PKEY_KEY_PARAMETERS, libCtx, NULL);
    err = dctx == NULL;
    if (err == 0) {
        /* Decode the parameters */
        err = OSSL_DECODER_from_data(dctx, &inptr, &inlen) != 1;
    }

    if (err == 0) {
        /* Create key generation context */
        ctx = EVP_PKEY_CTX_new_from_pkey(libCtx, params, NULL);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        /* Generate key pair */
        err = EVP_PKEY_keygen(ctx, &key) != 1;
    }

#ifdef WOLFSSL_DH_EXTRA
    if (err == 0) {
        /* Get the size of the encoded public key */
        err = i2d_PUBKEY(key, NULL) <= 0;
    }
    if (err == 0) {
        der_len = i2d_PUBKEY(key, NULL);
        der = OPENSSL_malloc(der_len);
        err = der == NULL;
    }
    if (err == 0) {
        unsigned char *p = der;
        err = i2d_PUBKEY(key, &p) <= 0;
    }
    if (err == 0) {
        spki = der;
        der = NULL;
        spki_len = der_len;
    }
    /* We were previously producing an empty subject public key info which was
     * too short. We are still producing a dhKeyAgreement SPKI instead of a
     * PKCS3 key, which should be fine for now but means we can't directly
     * compare outputs with openssl. For now lets just make sure the SPKI
     * encoding length is reasonable, about 260 for an empty SPKI */
    if (err == 0 && spki_len < 300) {
        PRINT_MSG("SPKI is too short");
        err = 1;
    }

    if (der) {
        OPENSSL_free(spki);
    }
    if (spki) {
        OPENSSL_free(spki);
    }
#endif /* WOLFSSL_DH_EXTRA */
    EVP_PKEY_free(key);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);
    OSSL_DECODER_CTX_free(dctx);

    return err;
}

/**
 * Test DH key generation using the krb5 test parameters.
 *
 * @param [in] data  Unused.
 * @return  1 on success.
 * @return  0 on failure.
 */
int test_dh_krb5_keygen(void *data)
{
    int err = 0;

    (void)data;

    err = test_dh_krb5_keygen_ex(osslLibCtx);
    if (err == 0) {
        err = test_dh_krb5_keygen_ex(wpLibCtx);
    }
    return err;
}

/* Generated offline with Python (g = 2):
 *   p = int.from_bytes(dh_p, 'big')
 *   pubA = pow(g, privA, p); pubB = pow(g, privB, p)
 *   shared = pow(pubB, privA, p)
 * privA was fixed and privB incremented until len(shared) < len(dh_p), i.e.
 * the shared secret has a leading zero byte (a ~1/256 chance per try). Only
 * privA, pubA (our key) and pubB (peer public) are needed at run time. */
static const unsigned char dh_pad_privA[] = {
    0xa3, 0x7f, 0x2c, 0x9e, 0x1b, 0x4d, 0x60, 0x58,
    0xf3, 0xc2, 0xa1, 0x90, 0x7e, 0x5d, 0x4b, 0x3c,
    0x2f, 0x19, 0x08, 0xe7, 0xd6, 0xc5, 0xb4, 0xa3,
    0x92, 0x81, 0x70, 0x6f, 0x5e, 0x4d, 0x3c, 0x2b
};

static const unsigned char dh_pad_pubA[] = {
    0x9c, 0x6c, 0xbc, 0xee, 0xdd, 0x3b, 0x2b, 0xc2,
    0x47, 0x68, 0x71, 0xf1, 0xd2, 0x2d, 0x71, 0x95,
    0x7c, 0xac, 0xb0, 0x5c, 0x82, 0x3f, 0x4a, 0xa3,
    0x71, 0x7c, 0x76, 0xd5, 0xcc, 0x28, 0x30, 0xfd,
    0x2c, 0x23, 0xf8, 0x32, 0x02, 0x12, 0xee, 0xbc,
    0x7b, 0x29, 0x17, 0x98, 0xd2, 0x84, 0x6e, 0x53,
    0x05, 0x4f, 0xb5, 0x75, 0x6d, 0xc2, 0x54, 0x41,
    0x62, 0x09, 0xf5, 0x0a, 0x6d, 0x96, 0xcc, 0x4a,
    0xbc, 0xa3, 0x57, 0x46, 0x73, 0xd6, 0x1c, 0x49,
    0xbc, 0x11, 0x47, 0x88, 0x53, 0x66, 0x26, 0xc0,
    0xa3, 0x25, 0x64, 0x9a, 0xfd, 0xd1, 0x1f, 0xf9,
    0x9a, 0xe7, 0xc1, 0x22, 0x97, 0x7f, 0xec, 0xe6,
    0x68, 0xca, 0xc8, 0x08, 0xd2, 0x9f, 0x0c, 0x33,
    0xb5, 0xd6, 0x0d, 0x7c, 0x34, 0x81, 0x8f, 0x53,
    0x1e, 0x8e, 0x95, 0xc9, 0xa2, 0x5e, 0xcb, 0xd4,
    0xa6, 0xd4, 0xe6, 0x4d, 0xa9, 0x94, 0xa0, 0x8a,
    0xf2, 0x14, 0x94, 0x30, 0xb6, 0x40, 0x77, 0x43,
    0xb0, 0xe5, 0x84, 0x9c, 0x91, 0xc7, 0xe1, 0x7f,
    0xa7, 0xd5, 0x61, 0x8d, 0x13, 0x7f, 0x6f, 0xf8,
    0xd1, 0x9c, 0x5e, 0xf5, 0x18, 0x2d, 0x36, 0x28,
    0x04, 0x92, 0x0a, 0xe4, 0xcd, 0xea, 0xd8, 0xdc,
    0x72, 0x35, 0xee, 0x89, 0x2a, 0xbc, 0x15, 0x81,
    0x17, 0xb3, 0xc3, 0xa6, 0x7a, 0x63, 0xff, 0xb5,
    0x2a, 0xc5, 0x6b, 0xfe, 0x96, 0x2b, 0xc3, 0x41,
    0xed, 0x85, 0xed, 0xd8, 0x9d, 0x56, 0x1d, 0xa7,
    0xc1, 0x87, 0xd8, 0x67, 0xc8, 0x76, 0x89, 0x01,
    0xb3, 0x21, 0x55, 0xab, 0x7f, 0x2e, 0x09, 0x74,
    0x9f, 0x30, 0xbd, 0xe7, 0x17, 0x5e, 0x9e, 0x52,
    0xb3, 0x12, 0x81, 0x65, 0xdd, 0xf0, 0x84, 0x59,
    0x55, 0xf1, 0x36, 0x80, 0x43, 0x6d, 0x05, 0xdc,
    0xd8, 0x6c, 0x74, 0xd3, 0x5c, 0x83, 0xd8, 0x72,
    0x94, 0x25, 0x65, 0xbc, 0x65, 0xb5, 0x77, 0xb9
};

static const unsigned char dh_pad_pubB[] = {
    0x46, 0x95, 0xfe, 0xc5, 0x41, 0x15, 0x13, 0xcb,
    0x1b, 0xb2, 0x7f, 0xe2, 0xe0, 0x35, 0xdf, 0xe0,
    0x12, 0x33, 0x77, 0x6d, 0xae, 0xb7, 0x87, 0x31,
    0x9c, 0x4c, 0x2f, 0x81, 0xcc, 0x6b, 0x34, 0x87,
    0x3a, 0x58, 0x69, 0x04, 0xfb, 0x3c, 0x3b, 0x67,
    0xeb, 0x17, 0xfe, 0x07, 0x79, 0x36, 0xff, 0x49,
    0x2e, 0xb8, 0x0c, 0x7d, 0x92, 0xa9, 0x48, 0xe8,
    0x5b, 0xb4, 0xe4, 0x9b, 0x37, 0x96, 0x7c, 0x1a,
    0xc1, 0x49, 0xef, 0x3b, 0x6e, 0xc7, 0x97, 0x20,
    0xef, 0x49, 0xfc, 0x8f, 0x0e, 0x67, 0xd1, 0xfb,
    0x4a, 0x4c, 0xcd, 0xed, 0x8a, 0x7a, 0x8a, 0xfc,
    0xa0, 0x62, 0x3c, 0x3e, 0x72, 0xc6, 0x85, 0xc8,
    0xb6, 0x35, 0xd1, 0xf4, 0xb9, 0x27, 0xd7, 0x69,
    0x5c, 0xf8, 0x4d, 0x15, 0x01, 0x42, 0xd7, 0xfc,
    0x77, 0x4a, 0x36, 0x35, 0xf0, 0x8d, 0xdb, 0x9f,
    0x8a, 0xa6, 0xeb, 0xc6, 0x73, 0xc1, 0xe0, 0x71,
    0xb8, 0xaa, 0xa9, 0x6e, 0x72, 0x3f, 0x8d, 0x4c,
    0x1d, 0x6c, 0x5b, 0x82, 0x93, 0xe6, 0x04, 0x82,
    0xce, 0x14, 0x8c, 0xb7, 0x3f, 0x00, 0xbf, 0x2a,
    0x6c, 0x60, 0x12, 0xb0, 0x0b, 0xba, 0x12, 0x08,
    0x5a, 0xa9, 0x99, 0x43, 0xe1, 0x82, 0x54, 0x44,
    0xda, 0x0e, 0x94, 0xd1, 0xe1, 0x1d, 0x27, 0xef,
    0xa7, 0x74, 0x23, 0x3f, 0xfb, 0x4b, 0x3f, 0x57,
    0xd0, 0x2f, 0x65, 0x3f, 0x5e, 0x00, 0x91, 0xc4,
    0x73, 0x73, 0xd2, 0xee, 0xe4, 0xb4, 0x6a, 0x94,
    0x5f, 0xa7, 0x5d, 0x73, 0x8c, 0x72, 0x8d, 0x33,
    0x48, 0x7c, 0x20, 0x1b, 0x1b, 0x33, 0x48, 0xd4,
    0xf7, 0x20, 0x60, 0x5d, 0x14, 0x39, 0x80, 0x13,
    0xd8, 0x28, 0x4e, 0x6e, 0xcf, 0xe4, 0x21, 0x1c,
    0x71, 0x80, 0x58, 0x8f, 0x8f, 0x85, 0x08, 0x61,
    0xcf, 0x5f, 0x1c, 0xc8, 0x28, 0x41, 0x1f, 0xdd,
    0x84, 0x04, 0x50, 0xa3, 0xfe, 0x78, 0xc7, 0x43
};

/* Build a DH EVP_PKEY from the fixed dh_p/dh_g group with the given public and
 * optional private key material. Used by the padding regression. */
static int test_dh_key_from_fixed(EVP_PKEY **pkey, const unsigned char *pub,
    size_t pubLen, const unsigned char *priv, size_t privLen)
{
    int err = 0;
    DH *dh = NULL;
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    BIGNUM *pubBn = NULL;
    BIGNUM *privBn = NULL;

    dh = DH_new();
    err = dh == NULL;
    if (err == 0) {
        p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
        g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
        err = (p == NULL) || (g == NULL);
    }
    if (err == 0) {
        err = DH_set0_pqg(dh, p, NULL, g) == 0;
        if (err == 0) {
            /* DH_set0_pqg takes ownership on success. */
            p = NULL;
            g = NULL;
        }
    }
    if (err == 0) {
        pubBn = BN_bin2bn(pub, (int)pubLen, NULL);
        err = pubBn == NULL;
    }
    if (err == 0 && priv != NULL) {
        privBn = BN_bin2bn(priv, (int)privLen, NULL);
        err = privBn == NULL;
    }
    if (err == 0) {
        err = DH_set0_key(dh, pubBn, privBn) == 0;
        if (err == 0) {
            /* DH_set0_key takes ownership on success. */
            pubBn = NULL;
            privBn = NULL;
        }
    }
    if (err == 0) {
        *pkey = EVP_PKEY_new();
        err = *pkey == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_set1_DH(*pkey, dh) != 1;
    }

    BN_free(pubBn);
    BN_free(privBn);
    BN_free(p);
    BN_free(g);
    DH_free(dh);
    return err;
}

/* Derive a shared secret between keyA (priv) and keyB (peer) using libCtx,
 * setting the OSSL_EXCHANGE_PARAM_PAD parameter to `pad`. The caller owns the
 * returned buffer and must free it with OPENSSL_free. */
static int test_dh_derive_with_pad(OSSL_LIB_CTX *libCtx, EVP_PKEY *keyA,
    EVP_PKEY *keyB, int pad, unsigned char **secret, size_t *secretLen)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    ctx = EVP_PKEY_CTX_new_from_pkey(libCtx, keyA, NULL);
    err = ctx == NULL;
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) <= 0;
    }
    if (err == 0) {
        params[0] = OSSL_PARAM_construct_int(OSSL_EXCHANGE_PARAM_PAD, &pad);
        params[1] = OSSL_PARAM_construct_end();
        err = EVP_PKEY_CTX_set_params(ctx, params) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_set_peer(ctx, keyB) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, NULL, secretLen) <= 0;
    }
    if (err == 0) {
        *secret = (unsigned char*)OPENSSL_malloc(*secretLen);
        err = *secret == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, *secret, secretLen) <= 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

/**
 * Test DH shared secret front-padding via OSSL_EXCHANGE_PARAM_PAD.
 *
 * With padding enabled, the derived secret must be front-padded with zeros to
 * the prime byte length. With padding disabled, the secret retains its natural
 * length (which is shorter when the high bytes of g^(ab) mod p are zero).
 *
 * Uses fixed key material whose shared secret has a leading zero byte so the
 * front-padding code path is exercised deterministically.
 */
int test_dh_pad(void *data)
{
    int err = 0;
    EVP_PKEY *keyA = NULL;
    EVP_PKEY *keyB = NULL;
    unsigned char *secretPad = NULL;
    unsigned char *secretNoPad = NULL;
    size_t secretPadLen = 0;
    size_t secretNoPadLen = 0;
    const size_t maxLen = sizeof(dh_p);

    (void)data;

    PRINT_MSG("Test DH secret front-padding via OSSL_EXCHANGE_PARAM_PAD");

    /* keyA holds our private key; keyB provides the peer public key. */
    err = test_dh_key_from_fixed(&keyA, dh_pad_pubA, sizeof(dh_pad_pubA),
        dh_pad_privA, sizeof(dh_pad_privA));
    if (err == 0) {
        err = test_dh_key_from_fixed(&keyB, dh_pad_pubB, sizeof(dh_pad_pubB),
            NULL, 0);
    }

    /* Derive without padding: natural length must be shorter than the prime so
     * the padding path is actually exercised below. */
    if (err == 0) {
        err = test_dh_derive_with_pad(wpLibCtx, keyA, keyB, 0,
            &secretNoPad, &secretNoPadLen);
    }
    if (err == 0 && secretNoPadLen >= maxLen) {
        PRINT_ERR_MSG("Unpadded secret length %zu not shorter than prime "
            "length %zu; padding path not exercised", secretNoPadLen, maxLen);
        err = 1;
    }

    /* Derive with padding using the same keys: length must equal the prime. */
    if (err == 0) {
        err = test_dh_derive_with_pad(wpLibCtx, keyA, keyB, 1,
            &secretPad, &secretPadLen);
    }
    if (err == 0 && secretPadLen != maxLen) {
        PRINT_ERR_MSG("Padded secret length %zu != prime length %zu",
            secretPadLen, maxLen);
        err = 1;
    }

    /* The padded secret must be the unpadded secret front-padded with zeros. */
    if (err == 0) {
        size_t padBytes = maxLen - secretNoPadLen;
        size_t i;

        for (i = 0; (err == 0) && (i < padBytes); ++i) {
            if (secretPad[i] != 0) {
                PRINT_ERR_MSG("Padded secret byte %zu = 0x%02x, want 0",
                    i, secretPad[i]);
                err = 1;
            }
        }
        if (err == 0 && memcmp(secretPad + padBytes, secretNoPad,
                secretNoPadLen) != 0) {
            PRINT_ERR_MSG("Padded tail does not match unpadded secret");
            err = 1;
        }
    }

    OPENSSL_free(secretNoPad);
    OPENSSL_free(secretPad);
    EVP_PKEY_free(keyA);
    EVP_PKEY_free(keyB);

    return err;
}

#if defined(HAVE_X963_KDF) && defined(WP_HAVE_SHA256)
/* Apply X9.63 KDF using OpenSSL's reference implementation. */
static int test_dh_x963_kdf_ref(const unsigned char* secret, size_t secLen,
    const char* mdName, const unsigned char* ukm, size_t ukmLen,
    unsigned char* out, size_t outLen)
{
    int err = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    kdf = EVP_KDF_fetch(osslLibCtx, OSSL_KDF_NAME_X963KDF, NULL);
    err = kdf == NULL;
    if (err == 0) {
        kctx = EVP_KDF_CTX_new(kdf);
        err = kctx == NULL;
    }
    if (err == 0) {
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char*)mdName, 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            (unsigned char*)secret, secLen);
        if (ukm != NULL && ukmLen > 0) {
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                (unsigned char*)ukm, ukmLen);
        }
        *p = OSSL_PARAM_construct_end();

        err = EVP_KDF_derive(kctx, out, outLen, params) <= 0;
    }

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return err;
}

/* Derive raw DH shared secret (no KDF) using wolfProvider. Caller frees. */
static int test_dh_derive_raw(EVP_PKEY *key, EVP_PKEY *peerKey,
    unsigned char **pSecret, size_t *pSecretLen)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *secret = NULL;
    size_t len = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key, NULL);
    err = ctx == NULL;
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_set_peer(ctx, peerKey) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, NULL, &len) <= 0;
    }
    if (err == 0) {
        secret = (unsigned char*)OPENSSL_malloc(len);
        err = secret == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, secret, &len) <= 0;
    }
    if (err == 0) {
        *pSecret = secret;
        *pSecretLen = len;
        secret = NULL;
    }

    OPENSSL_free(secret);
    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_dh_derive_x963_raw(EVP_PKEY *key, EVP_PKEY *peerKey,
    const char* mdName, size_t outLen, const unsigned char* ukm, size_t ukmLen,
    unsigned char *out, size_t outBufLen, int *deriveRet, size_t *derivedLen)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[5];
    OSSL_PARAM *p = params;

    *deriveRet = 0;
    *derivedLen = outBufLen;

    ctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key, NULL);
    err = ctx == NULL;
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_set_peer(ctx, peerKey) <= 0;
    }
    if (err == 0) {
        /* wolfProvider maps the X942KDF-ASN1 type string to its internal X963
         * KDF implementation (wc_X963_KDF). */
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE,
            (char*)OSSL_KDF_NAME_X942KDF_ASN1, 0);
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST,
            (char*)mdName, 0);
        *p++ = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
            &outLen);
        if (ukm != NULL && ukmLen > 0) {
            *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_EXCHANGE_PARAM_KDF_UKM, (unsigned char*)ukm, ukmLen);
        }
        *p = OSSL_PARAM_construct_end();

        err = EVP_PKEY_CTX_set_params(ctx, params) != 1;
    }
    if (err == 0) {
        *deriveRet = EVP_PKEY_derive(ctx, out, derivedLen);
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

/* Derive via wolfProvider with X9.63 KDF parameters set, requiring success and
 * exactly outLen bytes of output. */
static int test_dh_derive_with_x963(EVP_PKEY *key, EVP_PKEY *peerKey,
    const char* mdName, size_t outLen, const unsigned char* ukm, size_t ukmLen,
    unsigned char *out, size_t outBufLen)
{
    int err = 0;
    int deriveRet = 0;
    size_t derivedLen = 0;

    err = test_dh_derive_x963_raw(key, peerKey, mdName, outLen, ukm, ukmLen,
        out, outBufLen, &deriveRet, &derivedLen);
    if (err == 0 && deriveRet <= 0) {
        err = 1;
    }
    if (err == 0 && derivedLen != outLen) {
        PRINT_ERR_MSG("KDF output length %zu != requested %zu", derivedLen,
            outLen);
        err = 1;
    }

    return err;
}

/**
 * Test DH key derivation through the X9.63 KDF path.
 *
 * The provider's WP_KDF_X963 branch in wp_dh_derive (1) allocates a temporary
 * buffer sized to the prime length, (2) runs the raw DH agreement into it,
 * (3) feeds the result through wc_X963_KDF, and (4) securely frees the
 * temporary. We validate by computing the same KDF output independently via
 * OpenSSL's X963KDF and comparing.
 */
int test_dh_x963_kdf(void *data)
{
    int err = 0;
    DH *dh = NULL;
    EVP_PKEY *params = NULL;
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    EVP_PKEY_CTX *kgCtx = NULL;
    EVP_PKEY *keyA = NULL;
    EVP_PKEY *keyB = NULL;
    unsigned char *raw = NULL;
    size_t rawLen = 0;
    unsigned char wpOut[96];
    unsigned char refOut[96];
    unsigned char tooSmallBuf[8];
    size_t tooSmallLen;
    static const unsigned char ukm[] = {
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
        0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90
    };
    static const struct {
        const char* md;
        size_t outLen;
        int withUkm;
    } cases[] = {
        { "SHA256", 16, 0 },
        { "SHA256", 32, 0 },
        { "SHA256", 48, 0 },
        { "SHA256", 64, 0 },
        { "SHA256", 32, 1 },
    };
    size_t i;

    (void)data;

    PRINT_MSG("DH X9.63 KDF derivation");

    dh = DH_new();
    err = dh == NULL;
    if (err == 0) {
        p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
        err = p == NULL;
    }
    if (err == 0) {
        g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
        err = g == NULL;
    }
    if (err == 0) {
        err = DH_set0_pqg(dh, p, NULL, g) == 0;
        if (err == 0) {
            p = NULL;
            g = NULL;
        }
    }
    if (err == 0) {
        params = EVP_PKEY_new();
        err = params == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_set1_DH(params, dh) != 1;
    }

    /* Generate one fresh key pair for both ends. */
    if (err == 0) {
        kgCtx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, params, NULL);
        err = kgCtx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(kgCtx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(kgCtx, &keyA) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(kgCtx, &keyB) != 1;
    }

    /* Snapshot the raw DH shared secret once - it's the same input the KDF
     * branch feeds to wc_X963_KDF regardless of requested output length. */
    if (err == 0) {
        err = test_dh_derive_raw(keyA, keyB, &raw, &rawLen);
    }

    for (i = 0; (err == 0) && (i < sizeof(cases) / sizeof(cases[0])); ++i) {
        const unsigned char *ukmPtr = cases[i].withUkm ? ukm : NULL;
        size_t ukmLen = cases[i].withUkm ? sizeof(ukm) : 0;

        memset(wpOut, 0, sizeof(wpOut));
        memset(refOut, 0, sizeof(refOut));

        err = test_dh_derive_with_x963(keyA, keyB, cases[i].md,
            cases[i].outLen, ukmPtr, ukmLen, wpOut, sizeof(wpOut));
        if (err == 0) {
            err = test_dh_x963_kdf_ref(raw, rawLen, cases[i].md, ukmPtr,
                ukmLen, refOut, cases[i].outLen);
        }
        if (err == 0 && memcmp(wpOut, refOut, cases[i].outLen) != 0) {
            PRINT_ERR_MSG("X9.63 KDF output mismatch (md=%s outLen=%zu ukm=%d)",
                cases[i].md, cases[i].outLen, cases[i].withUkm);
            PRINT_BUFFER("wolfProvider", wpOut, cases[i].outLen);
            PRINT_BUFFER("OpenSSL X963KDF", refOut, cases[i].outLen);
            err = 1;
        }
        /* No bytes beyond the requested length should have been written. */
        if (err == 0) {
            size_t j;
            for (j = cases[i].outLen; j < sizeof(wpOut); ++j) {
                if (wpOut[j] != 0) {
                    PRINT_ERR_MSG("KDF wrote past requested length at byte %zu",
                        j);
                    err = 1;
                    break;
                }
            }
        }
    }

    /* Failure mode: caller's buffer smaller than the requested KDF output.
     * The derive itself must fail rather than truncate or overflow, so assert
     * on the raw EVP_PKEY_derive() result. */
    if (err == 0) {
        int deriveRet = 1;
        size_t derivedLen = 0;

        tooSmallLen = sizeof(tooSmallBuf);
        err = test_dh_derive_x963_raw(keyA, keyB, "SHA256", 32, NULL, 0,
            tooSmallBuf, tooSmallLen, &deriveRet, &derivedLen);
        if (err == 0 && deriveRet > 0) {
            PRINT_ERR_MSG("DH X963 KDF derive accepted under-sized buffer "
                "(ret=%d, len=%zu)", deriveRet, derivedLen);
            err = 1;
        }
    }

    OPENSSL_free(raw);
    EVP_PKEY_CTX_free(kgCtx);
    EVP_PKEY_free(keyA);
    EVP_PKEY_free(keyB);
    EVP_PKEY_free(params);
    BN_free(p);
    BN_free(g);
    DH_free(dh);

    return err;
}
#endif /* HAVE_X963_KDF && WP_HAVE_SHA256 */

/* Pass an oversize OSSL_PARAM (>1024 bytes) for the FFC P component to
 * EVP_PKEY_fromdata so wp_mp_read_unsigned_bin_le (wp_params.c) hits its
 * size-guard branch via wp_dh_import_group. Expect failure rather than the
 * stack buffer overflow that would happen without the guard. */
int test_dh_fromdata_oversize(void *data)
{
    int err = 0;
    EVP_PKEY_CTX *ctx_wolf = NULL;
    EVP_PKEY *pkey_wolf = NULL;
    unsigned char p_oversize[2048];
    unsigned char g_buf[1] = { 0x02 };
    OSSL_PARAM params[3];
    int status;

    (void)data;
    memset(p_oversize, 0xAA, sizeof(p_oversize));

    PRINT_MSG("Testing EVP_PKEY_fromdata with oversize DH FFC_P component");

    ctx_wolf = EVP_PKEY_CTX_new_from_name(wpLibCtx, "DH", NULL);
    if (ctx_wolf == NULL) {
        err = 1;
    }

    if (err == 0) {
        err |= EVP_PKEY_fromdata_init(ctx_wolf) != 1;
    }

    if (err == 0) {
        params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P,
                                            p_oversize, sizeof(p_oversize));
        params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G,
                                            g_buf, sizeof(g_buf));
        params[2] = OSSL_PARAM_construct_end();

        status = EVP_PKEY_fromdata(ctx_wolf, &pkey_wolf,
                                   EVP_PKEY_KEY_PARAMETERS, params);
        if (status == 1) {
            PRINT_MSG("EVP_PKEY_fromdata unexpectedly succeeded with 2048-byte"
                      " FFC_P");
            err = 1;
        }
        EVP_PKEY_free(pkey_wolf);
    }

    EVP_PKEY_CTX_free(ctx_wolf);
    return err;
}

/*
 * Explicit FFC domain parameters with a composite modulus must be rejected by
 * EVP_PKEY_param_check (the explicit-parameter path was previously a no-op).
 */
int test_dh_param_check_explicit(void *data)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *checkCtx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[3];
    unsigned char p_composite[256];
    unsigned char g_buf[1] = { 0x02 };

    (void)data;

    /* 2048-bit even value: composite, so not a valid DH modulus. */
    memset(p_composite, 0xFF, sizeof(p_composite));
    p_composite[sizeof(p_composite) - 1] = 0xFE;

    ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, "DH", NULL);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        err = EVP_PKEY_fromdata_init(ctx) != 1;
    }
    if (err == 0) {
        params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P,
                                            p_composite, sizeof(p_composite));
        params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G,
                                            g_buf, sizeof(g_buf));
        params[2] = OSSL_PARAM_construct_end();
        err = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS,
                                params) != 1;
    }
    if (err == 0) {
        checkCtx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, pkey, NULL);
        err = checkCtx == NULL;
    }
    if (err == 0 && EVP_PKEY_param_check(checkCtx) == 1) {
        PRINT_ERR_MSG("param_check accepted a composite DH modulus");
        err = 1;
    }

    EVP_PKEY_CTX_free(checkCtx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return err;
}

/*
 * A non-NUL-terminated GROUP_NAME param must not cause an out-of-bounds read
 * in the DH group-name comparison.
 */
int test_dh_import_group_no_nul(void *data)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];
    char *name = NULL;

    (void)data;

    name = OPENSSL_malloc(9);
    if (name == NULL) {
        err = 1;
    }
    if (err == 0) {
        memcpy(name, "ffdhe2048", 9);
        ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, "DH", NULL);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_fromdata_init(ctx) != 1;
    }
    if (err == 0) {
        params[0].key = OSSL_PKEY_PARAM_GROUP_NAME;
        params[0].data_type = OSSL_PARAM_UTF8_STRING;
        params[0].data = name;
        params[0].data_size = 9;
        params[0].return_size = 0;
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS,
                params) != 1) {
            PRINT_ERR_MSG("DH group import failed for valid group name");
            err = 1;
        }
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(name);
    return err;
}

#endif /* WP_HAVE_DH */

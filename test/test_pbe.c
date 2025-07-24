/* test_pbe.c
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

#ifdef WP_HAVE_PBE

#if (!defined(NO_DES3) && defined(WP_HAVE_SHA1)) || \
    (defined(WP_HAVE_SHA256) && defined(WP_HAVE_AESCBC)) || \
    (defined(WP_HAVE_SHA384) && defined(WP_HAVE_AESCBC))
static const unsigned char pbeData[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};
#endif
#if !defined(NO_DES3) && defined(WP_HAVE_SHA1)
static const unsigned char pbeEncSha1Des3[] = {
    0x21, 0x8f, 0xbe, 0x10, 0x39, 0x45, 0xe0, 0x3c,
    0x60, 0xab, 0x31, 0x39, 0xe0, 0x3e, 0x00, 0xc5,
    0x0b, 0x21, 0x37, 0x70, 0xc8, 0x92, 0x1f, 0x70
};
#endif
#if defined(WP_HAVE_SHA256) && defined(WP_HAVE_AESCBC)
static const unsigned char pbeEncAes128Cbc[] = {
    0x03, 0x2f, 0xe3, 0xa9, 0x02, 0x95, 0xed, 0x66,
    0xad, 0xe9, 0x19, 0xed, 0xe9, 0xb7, 0xf4, 0xc8,
    0xc6, 0x63, 0x9a, 0xbc, 0x0c, 0xde, 0x71, 0xbd,
    0x22, 0x0d, 0xc8, 0xf1, 0x04, 0xcd, 0xe7, 0x28
};
#endif
#if defined(WP_HAVE_SHA384) && defined(WP_HAVE_AESCBC)
static const unsigned char pbeEncAes256Cbc[] = {
    0x67, 0x62, 0xb8, 0x31, 0xbb, 0xdd, 0x16, 0x17,
    0x88, 0x4f, 0x01, 0x8b, 0x10, 0x43, 0xd0, 0xb5,
    0xe1, 0x5a, 0x6f, 0x1f, 0xff, 0x39, 0x88, 0x4d,
    0x6b, 0x96, 0xfa, 0x32, 0xf7, 0x60, 0x89, 0x6c
};
#endif

#if !defined(NO_DES3) && defined(WP_HAVE_SHA1)
/* Format of parameters:
 *    SEQ
 *      OCT <salt>
 *      INT <iterations=10000>
 */
static const unsigned char pbeParamPbe[] = {
    0x30, 0x0e,
          0x04, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
          0x02, 0x02, 0x27, 0x10
};
#endif

#if defined(WP_HAVE_SHA256) && defined(WP_HAVE_AESCBC)
/* Format of parameters:
 *  SEQ {pbes2}
 *    SEQ {kdf}
 *      OBJ <pbkdf2>
 *      SEQ
 *        OCT <salt>
 *        INT <iterations=10000>
 *        [INT <keylength>]
 *        [SEQ {prf}
 *           OBJ <hmac=HMAC-SHA256>
 *         ]
 *    SEQ {enc_alg}
 *      OBJ <aes128-cbc>
 */
static const unsigned char pbeParamPbes2Aes128Cbc[] = {
    0x30, 0x39,
          0x30, 0x2a,
                0x06, 0x09,
                      0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0C,
                0x30, 0x1d,
                      0x04, 0x08,
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x02, 0x02, 0x27, 0x10,
                      0x02, 0x01, 0x10,
                      0x30, 0x0a,
                            0x06, 0x08,
                                  0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x09,
          0x30, 0x0b,
                0x06, 0x09,
                      0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x02,
};
#endif

#if defined(WP_HAVE_SHA384) && defined(WP_HAVE_AESCBC)
/* Format of parameters:
 *  SEQ {pbes2}
 *    SEQ {kdf}
 *      OBJ <pbkdf2>
 *      SEQ
 *        OCT <salt>
 *        INT <iterations=10000>
 *        [INT <keylength> not included]
 *        [SEQ {prf}
 *           OBJ <hmac=HMAC-SHA384>
 *         ]
 *    SEQ {enc_alg}
 *      OBJ <aes256-cbc>
 */
static const unsigned char pbeParamPbes2Aes256Cbc[] = {
    0x30, 0x36,
          0x30, 0x27,
                0x06, 0x09,
                      0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0C,
                0x30, 0x1a,
                      0x04, 0x08,
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x02, 0x02, 0x27, 0x10,
                      0x30, 0x0a,
                            0x06, 0x08,
                                  0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x0A,
          0x30, 0x0b,
                0x06, 0x09,
                      0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2A,
};
#endif

#if defined(WP_HAVE_AESCBC) || !defined(NO_DES3)
static int test_pbe_encipher(ASN1_OBJECT *obj, ASN1_TYPE *param,
    const unsigned char *in, size_t inLen, unsigned char *out, int *outLen,
    int enc_dec)
{
    int err = 0;
    int rc;
    EVP_CIPHER_CTX *ctx;
    int len;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        PRINT_MSG("Failed to create EVP_CIPHER_CTX");
        err = 1;
    }
    if (!err) {
        rc = EVP_PBE_CipherInit_ex(obj, "password12345678", 16, param, ctx,
            enc_dec, wpLibCtx, NULL);
        if (rc != 1) {
            PRINT_MSG("Failed to initialize PBE cipher");
            err = 1;
        }
    }
    if (!err) {
        rc = EVP_CipherUpdate(ctx, out, &len, in, (int)inLen);
        if (rc != 1) {
            PRINT_MSG("Failed to update PBE cipher");
            err = 1;
        }
    }
    if (!err) {
        *outLen = len;
        rc = EVP_CipherFinal_ex(ctx, out + len, &len);
        if (rc != 1) {
            PRINT_MSG("Failed to finalize PBE cipher");
            err = 1;
        }
    }
    if (!err) {
        *outLen += len;
    }

    EVP_CIPHER_CTX_free(ctx);
    return err;
}

static int test_pbe_op(int nid, const unsigned char* params, int paramsLen,
    const unsigned char *in, size_t inLen, unsigned char *out, int *outLen,
    int enc_dec)
{
    int err = 0;
    int rc;
    ASN1_OBJECT *obj = OBJ_nid2obj(nid);
    ASN1_TYPE *param = NULL;
    ASN1_STRING *string = NULL;

    param = ASN1_TYPE_new();
    if (param == NULL) {
        PRINT_MSG("Failed to create ASN1_TYPE");
        err = 1;
    }
    if (!err) {
        string = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
        if (string == NULL) {
            PRINT_MSG("Failed to create ASN1_STRING");
            err = 1;
        }
    }
    if (!err) {
        rc = ASN1_STRING_set(string, params, paramsLen);
        if (rc != 1) {
            PRINT_MSG("Failed to set parameters into ASN1_STRING");
            err = 1;
        }
    }
    if (!err) {
        ASN1_TYPE_set(param, V_ASN1_SEQUENCE, string);
        string = NULL;

        err = test_pbe_encipher(obj, param, in, inLen, out, outLen, enc_dec);
    }

    ASN1_STRING_free(string);
    ASN1_TYPE_free(param);

    return err;
}
#endif

#if !defined(NO_DES3) && defined(WP_HAVE_SHA1)
static int test_pbe_sha1_des3_pbkdf1_op(const unsigned char *in, size_t inLen,
    unsigned char *out, int *outLen, int enc_dec)
{
    return test_pbe_op(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, pbeParamPbe,
        sizeof(pbeParamPbe), in, inLen, out, outLen, enc_dec);
}

static int test_pbe_sha1_des3_pbkdf1(void)
{
    int err;
    unsigned char pbeEnc[sizeof(pbeData) + 8];
    unsigned char pbeDec[sizeof(pbeData) + 8];
    int encLen;
    int decLen;

    PRINT_MSG("Encrypt");
    err = test_pbe_sha1_des3_pbkdf1_op(pbeData, sizeof(pbeData), pbeEnc,
        &encLen, 1);
    if (!err) {
        if ((encLen != (int)sizeof(pbeEncSha1Des3)) ||
            memcmp(pbeEncSha1Des3, pbeEnc, encLen) != 0) {
            PRINT_MSG("Different encrypted data");
            PRINT_BUFFER("PBE encrypted", pbeEnc, encLen);
            err = 1;
        }
    }
    if (!err) {
        PRINT_MSG("Decrypt");
        err = test_pbe_sha1_des3_pbkdf1_op(pbeEnc, encLen, pbeDec,
            &decLen, 0);
    }
    if (!err) {
        if ((decLen != (int)sizeof(pbeData)) ||
            memcmp(pbeData, pbeDec, decLen) != 0) {
            PRINT_MSG("Different decrypted data");
            PRINT_BUFFER("PBE decrypted", pbeDec, decLen);
            err = 1;
        }
    }

    return err;
}
#endif

#if defined(WP_HAVE_SHA256) && defined(WP_HAVE_AESCBC)
static int test_pbe_pbes2_aes128_cbc_op(const unsigned char *in, size_t inLen,
    unsigned char *out, int *outLen, int enc_dec)
{
    return test_pbe_op(NID_pbes2, pbeParamPbes2Aes128Cbc,
        sizeof(pbeParamPbes2Aes128Cbc), in, inLen, out, outLen, enc_dec);
}

static int test_pbe_pbes2_aes128_cbc(void)
{
    int err;
    unsigned char pbeEnc[sizeof(pbeData) + 16];
    unsigned char pbeDec[sizeof(pbeData) + 16];
    int encLen;
    int decLen;

    PRINT_MSG("Encrypt");
    err = test_pbe_pbes2_aes128_cbc_op(pbeData, sizeof(pbeData), pbeEnc,
        &encLen, 1);
    if (!err) {
        if ((encLen != (int)sizeof(pbeEncAes128Cbc)) ||
            memcmp(pbeEncAes128Cbc, pbeEnc, encLen) != 0) {
            PRINT_MSG("Different encrypted data");
            PRINT_BUFFER("PBE encrypted", pbeEnc, encLen);
            err = 1;
        }
    }
    if (!err) {
        PRINT_MSG("Decrypt");
        err = test_pbe_pbes2_aes128_cbc_op(pbeEnc, encLen, pbeDec,
            &decLen, 0);
    }
    if (!err) {
        if ((decLen != (int)sizeof(pbeData)) ||
            memcmp(pbeData, pbeDec, decLen) != 0) {
            PRINT_MSG("Different decrypted data");
            PRINT_BUFFER("PBE decrypted", pbeDec, decLen);
            err = 1;
        }
    }

    return err;
}
#endif

#if defined(WP_HAVE_SHA384) && defined(WP_HAVE_AESCBC)
static int test_pbe_pbes2_aes256_cbc_op(const unsigned char *in, size_t inLen,
    unsigned char *out, int *outLen, int enc_dec)
{
    return test_pbe_op(NID_pbes2, pbeParamPbes2Aes256Cbc,
        sizeof(pbeParamPbes2Aes256Cbc), in, inLen, out, outLen, enc_dec);
}

static int test_pbe_pbes2_aes256_cbc(void)
{
    int err;
    unsigned char pbeEnc[sizeof(pbeData) + 16];
    unsigned char pbeDec[sizeof(pbeData) + 16];
    int encLen;
    int decLen;

    PRINT_MSG("Encrypt");
    err = test_pbe_pbes2_aes256_cbc_op(pbeData, sizeof(pbeData), pbeEnc,
        &encLen, 1);
    if (!err) {
        if ((encLen != (int)sizeof(pbeEncAes256Cbc)) ||
            memcmp(pbeEncAes256Cbc, pbeEnc, encLen) != 0) {
            PRINT_MSG("Different encrypted data");
            PRINT_BUFFER("PBE encrypted", pbeEnc, encLen);
            err = 1;
        }
    }
    if (!err) {
        PRINT_MSG("Decrypt");
        err = test_pbe_pbes2_aes256_cbc_op(pbeEnc, encLen, pbeDec,
            &decLen, 0);
    }
    if (!err) {
        if ((decLen != (int)sizeof(pbeData)) ||
            memcmp(pbeData, pbeDec, decLen) != 0) {
            PRINT_MSG("Different decrypted data");
            PRINT_BUFFER("PBE decrypted", pbeDec, decLen);
            err = 1;
        }
    }

    return err;
}
#endif

int test_pbe(void *data)
{
    int err = 0;

    (void)data;

#ifdef NO_PWDBASED
    PRINT_MSG("Not using wolfProvider - PBKDF not available in wolfCrypt");
#endif

#if !defined(NO_DES3) && defined(WP_HAVE_SHA1)
    PRINT_MSG("PBE DES-EDE3-CBC SHA-1");
    err = test_pbe_sha1_des3_pbkdf1();
#endif
#if defined(WP_HAVE_SHA256) && defined(WP_HAVE_AESCBC)
    if (err == 0) {
        PRINT_MSG("PBES2 AES128-CBC HMAC-SHA-256");
        err = test_pbe_pbes2_aes128_cbc();
    }
#endif
#if defined(WP_HAVE_SHA384) && defined(WP_HAVE_AESCBC)
    if (err == 0) {
        PRINT_MSG("PBES2 AES256-CBC HMAC-SHA-384");
        err = test_pbe_pbes2_aes256_cbc();
    }
#endif

    return err;
}

#endif /* WP_HAVE_PBE */


#include <stdio.h>
#include <string.h>
#include <cjose/cjose.h>

int main(void) {
    cjose_err err = {0};
    // 32-byte HMAC key (octet JWK)
    uint8_t key[32]; for (int i=0;i<32;i++) key[i]=(uint8_t)i;
    cjose_jwk_t *jwk = cjose_jwk_create_oct_spec(key, sizeof(key), &err);

    cjose_header_t *hdr = cjose_header_new(&err);
    cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_HS256, &err);

    const char *msg = "hello cjose";
    cjose_jws_t *jws = cjose_jws_sign(jwk, hdr, (const uint8_t*)msg, strlen(msg), &err);

    const char *compact = NULL;
    cjose_jws_export(jws, &compact, &err);

    cjose_jws_t *parsed = cjose_jws_import(compact, strlen(compact), &err);
    if (!cjose_jws_verify(parsed, jwk, &err)) return 2;

    uint8_t *pt = NULL; size_t pt_len = 0;
    cjose_jws_get_plaintext(parsed, &pt, &pt_len, &err);

    int ok = (pt_len == strlen(msg) && memcmp(pt, msg, pt_len) == 0);
    cjose_jws_release(parsed); cjose_jws_release(jws); cjose_header_release(hdr); cjose_jwk_release(jwk);
    if (!ok) return 3;
    puts("OK: cjose JWS HS256 sign+verify");
    return 0;
}

// PPP crypto smoke test (no provider loading/listing)
// Checks SHA1, MD4 (NT hash), HMAC-MD5, DES-ECB, RC4 via OpenSSL 3 EVP fetch.
// Prints which provider actually serviced each algorithm (informational).
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/hmac.h>

static void hex(const unsigned char *b, size_t n, char *out) {
    static const char d[] = "0123456789abcdef";
    for (size_t i=0;i<n;i++){ out[2*i]=d[b[i]>>4]; out[2*i+1]=d[b[i]&0xF]; }
    out[2*n]='\0';
}
static const char* prov_name_from_md(const EVP_MD *md){
    const OSSL_PROVIDER *p = EVP_MD_get0_provider(md);
    return p ? OSSL_PROVIDER_get0_name(p) : "<unknown>";
}
static const char* prov_name_from_cipher(const EVP_CIPHER *c){
    const OSSL_PROVIDER *p = EVP_CIPHER_get0_provider(c);
    return p ? OSSL_PROVIDER_get0_name(p) : "<unknown>";
}

static int check_digest(const char *name, const char *propq,
                        const unsigned char *msg, size_t msglen,
                        const char *expect_hex) {
    int rc = -1;
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fprintf(stderr, "EVP_MD_CTX_new failed\n"); return rc; }
    EVP_MD *md = EVP_MD_fetch(NULL, name, propq);
    if (!md) { printf("SKIP %-10s (unavailable)\n", name); EVP_MD_CTX_free(ctx); return -2; }
    if (!EVP_DigestInit_ex(ctx, md, NULL) ||
        !EVP_DigestUpdate(ctx, msg, msglen) ||
        !EVP_DigestFinal_ex(ctx, out, &outlen)) {
        fprintf(stderr, "EVP_Digest* failed for %s\n", name);
        EVP_MD_free(md); EVP_MD_CTX_free(ctx); return rc;
    }
    char got[2*EVP_MAX_MD_SIZE+1]; hex(out, outlen, got);
    printf("OK   %-10s provider=%s  digest=%s\n", name, prov_name_from_md(md), got);
    rc = (0 == strcasecmp(got, expect_hex)) ? 0 : 1;
    if (rc) fprintf(stderr, "MISMATCH %s\n  expected: %s\n  got:      %s\n", name, expect_hex, got);
    EVP_MD_free(md); EVP_MD_CTX_free(ctx);
    return rc;
}

static int check_hmac(const char *mdname, const char *propq,
                      const unsigned char *key, size_t klen,
                      const unsigned char *msg, size_t mlen,
                      const char *expect_hex) {
    int rc = -1;
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen = 0;
    EVP_MD *md = EVP_MD_fetch(NULL, mdname, propq);
    if (!md) { printf("SKIP HMAC-%-6s (unavailable)\n", mdname); return -2; }
    if (!HMAC(md, key, (int)klen, msg, mlen, out, &outlen)) {
        fprintf(stderr, "HMAC(%s) failed\n", mdname);
        EVP_MD_free(md);
        return rc;
    }
    char got[2*EVP_MAX_MD_SIZE+1]; hex(out, outlen, got);
    printf("OK   HMAC-%-6s provider=%s  mac=%s\n", mdname, prov_name_from_md(md), got);
    rc = (0 == strcasecmp(got, expect_hex)) ? 0 : 1;
    if (rc) fprintf(stderr, "MISMATCH HMAC-%s\n  expected: %s\n  got:      %s\n", mdname, expect_hex, got);
    EVP_MD_free(md);
    return rc;
}

static int check_cipher_block(const char *cname, const char *propq,
                              const unsigned char *key, size_t klen,
                              const unsigned char *in, size_t ilen,
                              const char *expect_hex, int disable_pad) {
    (void)klen;
    int rc = -1;
    EVP_CIPHER *ciph = EVP_CIPHER_fetch(NULL, cname, propq);
    if (!ciph) { printf("SKIP %-10s (unavailable)\n", cname); return -2; }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { fprintf(stderr, "EVP_CIPHER_CTX_new failed\n"); EVP_CIPHER_free(ciph); return rc; }
    if (!EVP_EncryptInit_ex2(ctx, ciph, key, NULL, NULL)) { fprintf(stderr, "EncryptInit %s failed\n", cname); goto done; }
    if (disable_pad) EVP_CIPHER_CTX_set_padding(ctx, 0);

    unsigned char out[128]; int outl1=0, outl2=0;
    if (!EVP_EncryptUpdate(ctx, out, &outl1, in, (int)ilen)) { fprintf(stderr, "EncryptUpdate %s failed\n", cname); goto done; }
    if (!EVP_EncryptFinal_ex(ctx, out+outl1, &outl2)) { fprintf(stderr, "EncryptFinal %s failed\n", cname); goto done; }

    char got[2*128+1]; hex(out, outl1+outl2, got);
    printf("OK   %-10s provider=%s  ct=%s\n", cname, prov_name_from_cipher(ciph), got);
    rc = (0 == strcasecmp(got, expect_hex)) ? 0 : 1;
    if (rc) fprintf(stderr, "MISMATCH %s\n  expected: %s\n  got:      %s\n", cname, expect_hex, got);

done:
    EVP_CIPHER_free(ciph);
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static int check_stream_rc4(const char *propq,
                            const unsigned char *key, size_t klen,
                            size_t nbytes, const char *expect_hex) {
    (void)klen;
    int rc = -1;
    EVP_CIPHER *ciph = EVP_CIPHER_fetch(NULL, "RC4", propq);
    if (!ciph) { printf("SKIP RC4       (unavailable)\n"); return -2; }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { fprintf(stderr, "EVP_CIPHER_CTX_new failed\n"); EVP_CIPHER_free(ciph); return rc; }
    if (!EVP_EncryptInit_ex2(ctx, ciph, key, NULL, NULL)) { fprintf(stderr, "EncryptInit RC4 failed\n"); goto done; }

    unsigned char in[64]={0}, out[64]={0}; int outl=0, tmp=0;
    if (nbytes > sizeof(in)) nbytes = sizeof(in);
    if (!EVP_EncryptUpdate(ctx, out, &outl, in, (int)nbytes)) { fprintf(stderr, "RC4 update failed\n"); goto done; }
    if (!EVP_EncryptFinal_ex(ctx, out+outl, &tmp)) { fprintf(stderr, "RC4 final failed\n"); goto done; } outl += tmp;

    char got[2*64+1]; hex(out, outl, got);
    printf("OK   RC4        provider=%s  keystream=%s\n", prov_name_from_cipher(ciph), got);
    rc = (0 == strncasecmp(got, expect_hex, (int)strlen(expect_hex))) ? 0 : 1;
    if (rc) fprintf(stderr, "MISMATCH RC4\n  expected: %s\n  got:      %s\n", expect_hex, got);

done:
    EVP_CIPHER_free(ciph);
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int main(void){
    const char *propq = getenv("PROP_QUERY"); // optional (e.g., "provider=wolfprov")
    int failures = 0;

    // SHA1("abc")
    { const unsigned char msg[] = "abc";
      int rc = check_digest("SHA1", propq, msg, 3, "a9993e364706816aba3e25717850c26c9cd0d89d");
      if (rc > 0) failures++; }

    // MD4(UTF16LE("password")) -> NT hash
    { const char *pw = "password"; size_t n = strlen(pw);
      unsigned char utf16le[128];
      for (size_t i=0;i<n;i++){ utf16le[2*i]=(unsigned char)pw[i]; utf16le[2*i+1]=0x00; }
      int rc = check_digest("MD4", propq, utf16le, 2*n, "8846f7eaee8fb117ad06bdd830b7586c");
      if (rc > 0) failures++; }

    // HMAC-MD5("Jefe", "what do ya want for nothing?")
    { const unsigned char key[] = "Jefe";
      const unsigned char msg[] = "what do ya want for nothing?";
      int rc = check_hmac("MD5", propq, key, strlen((char*)key), msg, strlen((char*)msg),
                          "750c783e6ab0b503eaa86e310a5db738");
      if (rc > 0) failures++; }

    // DES-ECB: K=133457799BBCDFF1, P=0123456789ABCDEF -> C=85E813540F0AB405
    { const unsigned char key[8] = {0x13,0x34,0x57,0x79,0x9b,0xbc,0xdf,0xf1};
      const unsigned char pt [8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
      int rc = check_cipher_block("DES-ECB", propq, key, sizeof(key), pt, sizeof(pt),
                                  "85e813540f0ab405", 1);
      if (rc > 0) failures++; }

    // RC4 keystream for key="Key" (first 16 bytes per RFC 6229)
    { const unsigned char key[] = {0x4b,0x65,0x79}; // "Key"
      int rc = check_stream_rc4(propq, key, sizeof(key), 16,
                                "eb9f7781b734ca72a7190ec8792e513f");
      if (rc > 0) failures++; }

    printf("\n=== Summary: %s ===\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}

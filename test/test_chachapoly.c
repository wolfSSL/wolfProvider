/* test_chacha20_poly1305.c */

#include "unit.h"

/* Test tls encryption flow used by openSSL s-server/client */
static int test_chacha20_poly1305_encrypt(const EVP_CIPHER *cipher, unsigned char *key, 
                                unsigned char *nonce, int nonceLen,
                                unsigned char *aad, int aadLen,
                                unsigned char *tag, int tagLen,
                                unsigned char *plaintext, int plaintext_len, 
                                unsigned char *ciphertext, int *ciphertext_len)
{
    int err = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int cipherLen = 0;
    int len = 0;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1;
    }

    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonceLen, NULL) != 1;
    }

    if (err == 0) {
        err = EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL) != 1;
    }

    if (err == 0) {
        err = EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, nonce) != 1;
    }
    
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, NULL, &len, aad, aadLen) != 1;
    }

    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1;
    }
    
    if (err == 0) {
        cipherLen = len;
        err = EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1;
    }

    if (err == 0) {
        cipherLen += len;
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tagLen, tag) != 1;
    }

    if (err == 0) {
        PRINT_BUFFER("Encrypted", ciphertext, cipherLen);
        PRINT_BUFFER("Tag", tag, tagLen);
    }

    *ciphertext_len = cipherLen;
    
    EVP_CIPHER_CTX_free(ctx);
   
    return err;
}

static int test_chacha20_poly1305_decrypt(const EVP_CIPHER *cipher, unsigned char *key,
                                    unsigned char *nonce, int nonceLen,
                                    unsigned char *aad, int aadLen,
                                    unsigned char *tag, int tagLen, 
                                    unsigned char *ciphertext, int ciphertext_len, 
                                    unsigned char *decrypttext, int *decrypttext_len)
{
    int err = 0;

    EVP_CIPHER_CTX *ctx = NULL;
    int decryptLen = 0;
    int len = 0;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1;
    }

    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonceLen, NULL) != 1;
    }

    if (err == 0) {
        err = EVP_DecryptInit_ex(ctx, NULL, NULL, key, NULL) != 1;
    }

    if (err == 0) {
        err = EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, nonce) != 1;
    }

    if (err == 0) {
        err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagLen, tag) != 1;
    }

    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, NULL, &len, aad, aadLen) != 1;
    }

    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, decrypttext, &len, ciphertext, ciphertext_len) != 1;
    }

    if (err == 0) {
        decryptLen = len;
        err = EVP_DecryptFinal_ex(ctx, decrypttext + len, &len) != 1; 
    }

    if (err == 0) {
        decryptLen += len;
        PRINT_BUFFER("Decrypted", decrypttext, decryptLen);
        PRINT_BUFFER("Tag", tag, tagLen);
    }
    else {
        fprintf(stderr, "Decryption failed: Tag mismatch or data corrupted\n");
    }

    *decrypttext_len = decryptLen;

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

int test_chacha20_poly1305(void *data)
{
    int err = 0;
    unsigned char key[32]; 
    unsigned char nonce[12]; 
    unsigned char aad[] = "Associated Data";
    unsigned char msg[] = "Secret Message!";
    unsigned char ciphertext[sizeof(msg)] = {0};
    unsigned char decrypted[sizeof(msg)] = {0};
    unsigned char tag[16] = {0};
    int ciphertext_len = 0;
    int decrypted_len = 0;
    EVP_CIPHER* ocipher = NULL;
    EVP_CIPHER* wcipher = NULL;

    (void)data;

    ocipher = EVP_CIPHER_fetch(osslLibCtx, "ChaCha20-Poly1305", "");
    wcipher = EVP_CIPHER_fetch(wpLibCtx, "ChaCha20-Poly1305", "");

    // Generate random key and nonce
    if (RAND_bytes(key, sizeof(key)) == 0) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(nonce, sizeof(nonce)) == 0) {
            err = 1;
        }
    }

    if (err == 0) {
        PRINT_BUFFER("Key", key, sizeof(key));
        PRINT_BUFFER("Nonce", nonce, sizeof(nonce));
        PRINT_BUFFER("Aad", aad, sizeof(aad));
        PRINT_BUFFER("Message", msg, sizeof(msg));

        PRINT_MSG("Encrypt with OpenSSL - TLS");
        err = test_chacha20_poly1305_encrypt(ocipher, key, nonce, sizeof(nonce), 
                                                aad, sizeof(aad), 
                                                tag, sizeof(tag),
                                                msg, sizeof(msg), 
                                                ciphertext, &ciphertext_len);
    }

    if (err == 0) {
        PRINT_MSG("Decrypt with wolfprovider - TLS");
        err = test_chacha20_poly1305_decrypt(wcipher, key, nonce, sizeof(nonce), 
                                                aad, sizeof(aad), 
                                                tag, sizeof(tag), 
                                                ciphertext, ciphertext_len,
                                                decrypted, &decrypted_len);
    }

    if (err == 0) {
        PRINT_MSG("Ensure the plain message and the decrypted message are the same.");
        err = memcmp(msg, decrypted, sizeof(msg)) != 0;
    }

    if (err == 0) {
        memset(ciphertext, 0, sizeof(ciphertext));
        memset(decrypted, 0, sizeof(decrypted));

        PRINT_MSG("Encrypt with wolfprovider - TLS");
        err = test_chacha20_poly1305_encrypt(wcipher, key, nonce, sizeof(nonce), 
                                                aad, sizeof(aad), 
                                                tag, sizeof(tag),
                                                msg, sizeof(msg), 
                                                ciphertext, &ciphertext_len);
    }

    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL - TLS");
        err = test_chacha20_poly1305_decrypt(ocipher, key, nonce, sizeof(nonce), 
                                                aad, sizeof(aad), 
                                                tag, sizeof(tag), 
                                                ciphertext, ciphertext_len,
                                                decrypted, &decrypted_len);
    }

    if (err == 0) {
        PRINT_MSG("Ensure the plain message and the decrypted message are the same.");
        err = memcmp(msg, decrypted, sizeof(msg)) != 0;
    }

    EVP_CIPHER_free(wcipher);
    EVP_CIPHER_free(ocipher);

    return err;
}
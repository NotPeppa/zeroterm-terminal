/* ZeroTerm strict leaf pin: shared verbatim by the plugin and runnable unit check. */
#ifndef ZT_STRICT_PIN_H
#define ZT_STRICT_PIN_H
#include <limits.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

static int zt_leaf_pin_matches(const unsigned char* pem, size_t length, const char* pin) {
    unsigned char digest[EVP_MAX_MD_SIZE], approved[32];
    unsigned int digest_length = 0;
    if (!pem || !length || length > INT_MAX || !pin || strlen(pin) != 64
            || strspn(pin, "0123456789abcdef") != 64)
        return 0;
    for (size_t i = 0; i < 32; i++) {
        const char* hex = "0123456789abcdef";
        approved[i] = ((strchr(hex, pin[i*2]) - hex) << 4)
                | (strchr(hex, pin[i*2+1]) - hex);
    }
    BIO* bio = BIO_new_mem_buf(pem, (int) length);
    if (!bio)
        return 0;
    /* FreeRDP supplies the leaf first, followed by any PEM chain. */
    X509* leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    int match = leaf && X509_digest(leaf, EVP_sha256(), digest, &digest_length)
            && digest_length == 32 && CRYPTO_memcmp(digest, approved, 32) == 0;
    X509_free(leaf);
    BIO_free(bio);
    return match;
}
#endif

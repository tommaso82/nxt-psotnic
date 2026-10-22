#include <sodium.h>

/* Configure probe: prove that the actual algorithms we use compile and link. */
int main(void)
{
    unsigned char salt[crypto_pwhash_SALTBYTES] = {0};
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES] = {0};
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] = {0};
    unsigned char plain[1] = {0};
    unsigned char encrypted[1];
    unsigned char mac[crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned long long maclen = 0;

    if(sodium_init() < 0) return 1;
    if(crypto_pwhash(key, sizeof(key), "x", 1, salt,
                     crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN,
                     crypto_pwhash_ALG_ARGON2ID13) != 0) return 1;
    return crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        encrypted, mac, &maclen, plain, sizeof(plain),
        NULL, 0, NULL, nonce, key);
}

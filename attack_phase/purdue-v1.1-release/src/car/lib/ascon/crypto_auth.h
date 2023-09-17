#ifndef __CRYPTO_AUTH_
#define __CRYPTO_AUTH_

int crypto_auth(unsigned char *out, const unsigned char *in,
                unsigned long long inlen, const unsigned char *k);

int crypto_auth_verify(const unsigned char *h, const unsigned char *in,
                       unsigned long long inlen, const unsigned char *k);

#endif  // __CRYPTO_AUTH_
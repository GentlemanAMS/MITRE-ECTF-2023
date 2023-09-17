#ifndef __CRYPTO_HASH_
#define __CRYPTO_HASH_

int crypto_hash(unsigned char *out, const unsigned char *in,
                unsigned long long inlen);

#endif  // __CRYPTO_HASH_

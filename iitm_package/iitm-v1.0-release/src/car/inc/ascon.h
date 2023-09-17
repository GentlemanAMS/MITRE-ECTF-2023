#ifndef ASCON_H_
#define ASCON_H_

#include "word.h"

/*
Initialize ASCON Cipher with nonce stored in array 'n' and key in 'k'
*/
state_t ascon_aeadinit(const uint8_t* n, const uint8_t* k);


/*
Starting with Associated data
*/
state_t ascon_adata(state_t s, const uint8_t* ad, uint32_t adlen);


/*
Encrypting plain text
*/
state_t ascon_encrypt(state_t s, uint8_t* c, const uint8_t* pt, uint32_t mlen);


/*
Decrypting cipher text
*/
state_t ascon_decrypt(state_t s, uint8_t* m, const uint8_t* c, uint32_t clen); 


/*
Calculating Authentication tag
*/
state_t ascon_final(state_t s, const uint8_t* k);


/*
ASCON AEAD Encryption

OUTPUTS
Cipher text will be stored in array 'c'
Cipher text lelngth will be stored in the memory location pointed by the pointer 'clen'

INPUTS
Plain text: array 'm'
Plain text length: 'mlen'
Associated data: array 'ad'
Associated data length: 'adlen'
Nonce: array 'npub'
Key: array 'k'
*/
int crypto_aead_encrypt(uint8_t* c, uint32_t* clen,
                        const uint8_t* m, uint32_t mlen,
                        const uint8_t* ad, uint32_t adlen,
                        const uint8_t* npub, const uint8_t* k);



/*
ASCON AEAD Decryption

OUTPUTS
Plain text will be stored in array 'm'
Plain text lelngth will be stored in the memory location pointed by the pointer 'cmlen'

INPUTS
Cipher text: array 'c'
Cipher text length: 'clen'
Associated data: array 'ad'
Associated data length: 'adlen'
Nonce: array 'npub'
Key: array 'k'
*/
int crypto_aead_decrypt(uint8_t* m, uint32_t* mlen,
                        const uint8_t* c, uint32_t clen, 
                        const uint8_t* ad, uint32_t adlen, 
                        const uint8_t* npub, const uint8_t* k);

#endif /* ASCON_H */

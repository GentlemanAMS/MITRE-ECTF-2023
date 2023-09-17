
#include "aes.h"
#include "hmac.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


extern const uint32_t n;
extern uint8_t *hk;
extern uint8_t *psk;
#include "params.h"

typedef struct
{
  uint8_t       magic[1];
  uint8_t       nonce[4];
  uint8_t       buffer[11];
} MESSAGE_PAYLOAD;

int main(int argc, char *argv[])
{
  MESSAGE_PAYLOAD payload = {0};
  struct AES_ctx ctx;

  uint8_t digest[20];

  AES_init_ctx(&ctx, psk); // configure keys

  payload.nonce[3] = (n >> 24) & 0xFF;
  payload.nonce[2] = (n >> 16) & 0xFF;
  payload.nonce[1] = (n >> 8) & 0xFF;
  payload.nonce[0] = n & 0xFF;

  payload.magic[0] = ACK_MAGIC;
  //payload.magic[0] = UNLOCK_MAGIC;
  memcpy(payload.buffer,&ACK_SUCCESS,11);
  //memcpy(payload.buffer,&UNLOCK_MSG,11);

  hmac_sha1(hk, 16, (uint8_t*)&payload, 16, digest);

  AES_ECB_encrypt(&ctx, (uint8_t*)&payload);

  for(int i = 0; i < 16; i++) printf("%.2X", digest[i]);
  printf("\n");

  for(int i = 0; i < 16; i++) printf("%.2X", ((uint8_t*)&payload)[i]);
  printf("\n");

  AES_ECB_decrypt(&ctx, (uint8_t*)&payload);
  for(int i = 0; i < 16; i++) printf("%c", ((char*)&payload)[i]);
  printf("\n");

  return 0;
}


/**
 * \addtogroup cc2538-ctr-state
 * @{
 *
 * \file
 * Implementation of the cc2538 AES-CTR-state driver
 */
#include "contiki.h"
#include "dev/rom-util.h"
#include "dev/ctr-state.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
/*---------------------------------------------------------------------------*/
void
ctr_state_init(aes_ctr_state_ctx *ctx, uint8_t* key, uint8_t keylen, const uint8_t* iv) {
  ctx->key_len = keylen;
  rom_util_memcpy(ctx->key, key, keylen);
  rom_util_memcpy(ctx->iv, iv, CTR_STATE_IVLEN);

  ctx->num = 0;
}

static uint8_t buf[CTR_STATE_BLOCKLEN];

uint8_t
ctr_state_crypt(aes_ctr_state_ctx *ctx, uint8_t *data, uint8_t datalen)
{
  uint32_t ctrl;
  uint8_t iv[16];
  uint8_t len = datalen;
  uint8_t offset = 0;
  uint8_t res = 0;

  /* Load key */
  res = aes_load_keys(ctx->key, (ctx->key_len == 16) ? AES_KEY_STORE_SIZE_KEY_SIZE_128 : AES_KEY_STORE_SIZE_KEY_SIZE_256, 1, 0);

  /* Program AES-CTR crypto operation */
  ctrl = (((16 >> 2) - 1) << AES_AES_CTRL_CTR_WIDTH_S) | /* CTR width */
    AES_AES_CTRL_CTR |                                   /* CTR */
    AES_AES_CTRL_DIRECTION_ENCRYPT;                      /* Encryption */

  if (ctx->num != 0) {
    /* Decrement Iv and handle underflow */
    for (uint8_t i = (CTR_STATE_IVLEN - 1); i >= 0; --i) {
      /* inc will owerflow */
      if (ctx->iv[i] == 0) {
        ctx->iv[i] = 255;
        continue;
      }
      ctx->iv[i] -= 1;
      break;
    }

    /* Initial counter */
    rom_util_memcpy((uint8_t *)iv, ctx->iv, CTR_STATE_IVLEN);

    rom_util_memcpy(buf+ctx->num, data, CTR_STATE_BLOCKLEN-ctx->num);

    aes_auth_crypt_start(ctrl, 0, iv, NULL, 0,
                         buf, buf, CTR_STATE_BLOCKLEN, NULL);

    len -= CTR_STATE_BLOCKLEN-ctx->num;
    offset += ctx->num;

    while (aes_auth_crypt_get_result(NULL, NULL) != CRYPTO_SUCCESS);

    rom_util_memcpy(data, buf+ctx->num, CTR_STATE_BLOCKLEN-ctx->num);

    ((uint32_t *)iv)[0] = REG(AES_AES_IV_0);
    ((uint32_t *)iv)[1] = REG(AES_AES_IV_1);
    ((uint32_t *)iv)[2] = REG(AES_AES_IV_2);
    ((uint32_t *)iv)[3] = REG(AES_AES_IV_3);
  } else {
    /* Initial counter */
    rom_util_memcpy((uint8_t *)iv, ctx->iv, CTR_STATE_IVLEN);
  }

  if (len > 0) {
    aes_auth_crypt_start(ctrl, 0, iv, NULL, 0, data+offset, data+offset, len, NULL);

    while (aes_auth_crypt_get_result(NULL, NULL) != CRYPTO_SUCCESS);

    ((uint32_t *)ctx->iv)[0] = REG(AES_AES_IV_0);
    ((uint32_t *)ctx->iv)[1] = REG(AES_AES_IV_1);
    ((uint32_t *)ctx->iv)[2] = REG(AES_AES_IV_2);
    ((uint32_t *)ctx->iv)[3] = REG(AES_AES_IV_3);

  } else {
    memcpy(ctx->iv, iv, CTR_STATE_IVLEN);
  }

  ctx->num = len % CTR_STATE_BLOCKLEN;

  return res;
}
/*---------------------------------------------------------------------------*/

/** @} */

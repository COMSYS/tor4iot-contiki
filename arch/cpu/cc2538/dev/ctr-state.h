/*
 * Implements CTR mode with state for counter and current IV.
 */
/**
 * \addtogroup cc2538-aes
 * @{
 *
 * \defgroup cc2538-ctr cc2538 AES-CTR-state
 *
 * Driver for the cc2538 AES-CTR mode with state of the security core
 * @{
 *
 * \file
 * Header file for the cc2538 AES-CTR-state driver
 */
#ifndef CTR_H_
#define CTR_H_

#include "contiki.h"
#include "dev/aes.h"

#include <stdbool.h>
#include <stdint.h>

#define CTR_STATE_BLOCKLEN 16
#define CTR_STATE_MAXKEYLEN 32
#define CTR_STATE_IVLEN 16

typedef struct aes_ctr_state_ctx {
  uint8_t iv[CTR_STATE_BLOCKLEN];
  uint8_t buffer[CTR_STATE_BLOCKLEN];
  uint8_t num;

  uint8_t key_len;
  uint8_t key[CTR_STATE_MAXKEYLEN];
} aes_ctr_state_ctx;

/*---------------------------------------------------------------------------*/
/** \name AES-CTR-state functions
 * @{
 */

void
ctr_state_init(aes_ctr_state_ctx *ctx, uint8_t* key, uint8_t keylen, const uint8_t* iv);

uint8_t
ctr_state_crypt(aes_ctr_state_ctx *ctx, uint8_t *data, uint8_t datalen);

/** @} */

#endif /* CTR_H_ */

/**
 * @}
 * @}
 */

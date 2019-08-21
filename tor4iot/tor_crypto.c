#include "tor_crypto.h"

#include "tor4iot.h"

#include "sha1.h"
#include "tinydtls.h"

/* RANDOM */

int
compute_random (uint8_t* target, uint8_t len)
{
  static uint8_t random[] =
    { 0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4,
      0x24, 0xb1, 0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
      0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c };
  for (uint8_t i = 0; i < len; i++)
    {
      target[i] = random[i % 32];
    }
  return 0;
}

/* AES */

void tor4iot_aes_init(t4i_aes_ctx *ctx, uint8_t* key, uint8_t keylen, const uint8_t* iv){
  LOG_DBG("Initializing AES with key: ");
  for (uint8_t i=0; i<keylen; i++) {
    LOG_DBG_("%02x", key[i]);
  }
  LOG_DBG_("\n");
  LOG_DBG("Set key material.\n");
  if (rijndael_set_key_enc_only(&ctx->aes, key, keylen*8) == -1){
      LOG_WARN("Setting key failed.\n");
  }
  memcpy(ctx->iv, iv, AES_BLOCKLEN);
  ctx->num = AES_BLOCKLEN;
}


void tor4iot_aes_crypt(t4i_aes_ctx *ctx, uint8_t *buf, size_t length, uint8_t init) {
  LOG_DBG("Before crypt: %02x %02x\n", buf[0], buf[1]);
  unsigned i;
  int bi;

  for (i = 0, bi = ctx->num; i < length; ++i, ++bi) {
    if (bi == AES_BLOCKLEN) {
	    rijndael_encrypt(&(ctx->aes), ctx->iv, ctx->buffer);

      for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi) {
        if (ctx->iv[bi] == 255) {
          ctx->iv[bi] = 0;
          continue;
        }
        ctx->iv[bi] += 1;
        break;
      }
      bi = 0;
    }

    buf[i] = (buf[i] ^ ctx->buffer[bi]);
  }

  ctx->num = bi;
  LOG_DBG("After crypt: %02x %02x\n", buf[0], buf[1]);
}

void tor4iot_aes_crypt_once(uint8_t *buf, size_t len, uint8_t *key, uint8_t *iv) {
  t4i_aes_ctx ctx;

  tor4iot_aes_init(&ctx, key, 16, iv);
  tor4iot_aes_crypt(&ctx, buf, len, 0);
}


/* HASH */

void
tor4iot_hmac_sha256 (void *out, const void *key, size_t key_len,
		     const void *msg, size_t msg_len)
{
  LOG_DBG("Performing hmac on %zd bytes of data:\n", msg_len);
  for (int i=0; i<msg_len; i++) {
      LOG_DBG_("%02x", ((uint8_t *)msg)[i]);
  }
  LOG_DBG_("\n");

  dtls_hmac_context_t *ctx;

  ctx = dtls_hmac_new(key, key_len);

  dtls_hmac_update(ctx, msg, msg_len);
  dtls_hmac_finalize(ctx, out);

  dtls_hmac_free(ctx);
}

static void
intermediate_sha1 (uint8_t* target, size_t size, SHA_CTX *context,
		   sha1_byte *data, unsigned int len)
{
  SHA_CTX tmp_ctx;
  uint8_t tmp_data[len];
  uint8_t digest[SHA1_DIGEST_LENGTH];

  memcpy (tmp_data, data, len);
  SHA1_Update (context, tmp_data, len);
  memcpy (&tmp_ctx, context, sizeof(SHA_CTX));

  SHA1_Final (digest, &tmp_ctx);
  memcpy (target, digest, size);
}

static void
intermediate_keccak(keccak_state *state, uint8_t *buf, size_t buflen, uint8_t *out, size_t outlen) {
  keccak_state tmp_state;

  if (keccak_digest_update(state, buf, buflen) != 0) {
    LOG_WARN("Error during keccak update.\n");
  }

  memcpy(&tmp_state, state, sizeof(keccak_state));

  if (keccak_digest_sum(state, out, outlen) != 0) {
    LOG_WARN("Error during keccak finalization\n");
  }
}

void
tor4iot_init_mac(t4i_mac_ctx *ctx) {
  LOG_DBG("Initializing MAC.\n");
  switch (ctx->type) {
    case undefined:
      LOG_WARN("Tried to initialize an undefined mac context.\n");
      break;
    case sha1:
      SHA1_Init (&ctx->sha);
      break;
    case keccak:
      if (keccak_digest_init(&ctx->keccak, 256) != 0) {
        LOG_WARN("Error during keccak init.\n");
      }
  }
}

void
tor4iot_update_mac(t4i_mac_ctx *ctx, uint8_t *buf, size_t buflen) {
  switch (ctx->type) {
    case undefined:
      LOG_WARN("Tried to calculate mac using an undefined context.\n");
      break;
    case sha1:
      SHA1_Update(&ctx->sha, buf, buflen);
      break;
    case keccak:
      if (keccak_digest_update(&ctx->keccak, buf, buflen) != 0) {
        LOG_WARN("Error during keccak update.\n");
      }
      break;
  }
}

void
tor4iot_intermediate_mac(t4i_mac_ctx *ctx, uint8_t *buf, size_t buflen, uint8_t *out, size_t outlen) {
  switch (ctx->type) {
    case undefined:
      LOG_WARN("Tried to calculate mac using an undefined context.\n");
      break;
    case sha1:
      intermediate_sha1(out, outlen, &ctx->sha, buf, buflen);
      break;
    case keccak:
      intermediate_keccak(&ctx->keccak, buf, buflen, out, outlen);
      break;
  }
}

#ifndef TOR_CRYPTO_H_
#define TOR_CRYPTO_H_

#include <stdint.h>
#include <stddef.h>

#include "tor4iot.h"

#include "tinydtls.h"

#include "sha1.h"
#include "keccak-tiny.h"

#define AES_BLOCKLEN 16

/**
 * Context of our own CTR implementation and AES.
 */
typedef struct t4i_aes_ctx {
	uint8_t iv[AES_BLOCKLEN];
	uint8_t buffer[AES_BLOCKLEN];
	uint8_t num;

	rijndael_ctx aes;
} t4i_aes_ctx;

enum t4i_mac_type {
	undefined, sha1, keccak
};

/**
 * Context for cell digest, either SHA1 or keccak.
 */
typedef struct t4i_mac_ctx {
	uint8_t type;
	union {
		SHA_CTX sha;
		keccak_state keccak;
	};
} t4i_mac_ctx;

/**
 * Compute a pseudo random phrase of length len.
 */
int
compute_random(uint8_t* target, uint8_t len);

/**
 * Scalar multiplication Curve25519.
 */
void
tor4iot_curve25519_smult(uint8_t* output, const uint8_t* secret,
		const uint8_t* point);

/**
 * Scalar multiplication with the predefined basepoint.
 */
void
tor4iot_curve25519_basepoint(uint8_t* public_key, const uint8_t* secret_key);

/**
 * Initialize AES context.
 */
void tor4iot_aes_init(t4i_aes_ctx *ctx, uint8_t* key, uint8_t keylen,
		const uint8_t* iv);

/**
 * Crypt inplace with AES.
 */
void tor4iot_aes_crypt(t4i_aes_ctx *ctx, uint8_t *buffer, size_t len,
		uint8_t init);

/**
 * AES CTR crypt without any state. Used for ticket decryption.
 */
void tor4iot_aes_crypt_once(uint8_t *buf, size_t len, uint8_t *key, uint8_t *iv);

/**
 * Compute HMAC with SHA256.
 */
void
tor4iot_hmac_sha256(void *out, const void *key, size_t key_len, const void *msg,
		size_t msg_len);

/**
 * Initialize MAC context.
 */
void
tor4iot_init_mac(t4i_mac_ctx *ctx);

/**
 * Update MAC context.
 */
void
tor4iot_update_mac(t4i_mac_ctx *ctx, uint8_t *buf, size_t buflen);

/**
 * Compute an intermediate MAC, i.e., save the MAC context for later use but
 * finalize for output.
 */
void
tor4iot_intermediate_mac(t4i_mac_ctx *ctx, uint8_t *buf, size_t buflen,
		uint8_t *out, size_t outlen);

#endif /* TOR_CRYPTO_H_ */

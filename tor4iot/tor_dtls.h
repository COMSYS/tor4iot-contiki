#ifndef TOR_DTLS_H_
#define TOR_DTLS_H_

#include "connection.h"

#ifdef DTLS_PSK
/* The PSK information for DTLS */
/* make sure that default identity and key fit into buffer, i.e.
 * sizeof(PSK_DEFAULT_IDENTITY) - 1 <= PSK_ID_MAXLEN and
 * sizeof(PSK_DEFAULT_KEY) - 1 <= PSK_MAXLEN
 */

#define PSK_ID_MAXLEN 32
#define PSK_MAXLEN 32
#define PSK_DEFAULT_IDENTITY "Client_identity"
#define PSK_DEFAULT_KEY      "secretPSK"
#endif /* DTLS_PSK */

#ifdef DTLS_ECC

static const unsigned char ecdsa_priv_key[] =
{
	0x41, 0xC1, 0xCB, 0x6B, 0x51, 0x24, 0x7A, 0x14,
	0x43, 0x21, 0x43, 0x5B, 0x7A, 0x80, 0xE7, 0x14,
	0x89, 0x6A, 0x33, 0xBB, 0xAD, 0x72, 0x94, 0xCA,
	0x40, 0x14, 0x55, 0xA1, 0x94, 0xA9, 0x49, 0xFA};

static const unsigned char ecdsa_pub_key_x[] =
{
	0x36, 0xDF, 0xE2, 0xC6, 0xF9, 0xF2, 0xED, 0x29,
	0xDA, 0x0A, 0x9A, 0x8F, 0x62, 0x68, 0x4E, 0x91,
	0x63, 0x75, 0xBA, 0x10, 0x30, 0x0C, 0x28, 0xC5,
	0xE4, 0x7C, 0xFB, 0xF2, 0x5F, 0xA5, 0x8F, 0x52};

static const unsigned char ecdsa_pub_key_y[] =
{
	0x71, 0xA0, 0xD4, 0xFC, 0xDE, 0x1A, 0xB8, 0x78,
	0x5A, 0x3C, 0x78, 0x69, 0x35, 0xA7, 0xCF, 0xAB,
	0xE9, 0x3F, 0x98, 0x72, 0x09, 0xDA, 0xED, 0x0B,
	0x4F, 0xAB, 0xC3, 0x6F, 0xC7, 0x72, 0xF8, 0x29};

#endif

/**
 * Initialize DTLS library.
 */
void
tor_dtls_init(void);

/**
 * Connect to IoT Entry using the parameters of conn.
 */
void
tor_dtls_connect(connection_t *conn);

/**
 * Disconnect from IoT Entry.
 */
int
tor_dtls_disconnect(connection_t *conn);

/**
 * Send data to IoT Entry.
 */
int
tor_dtls_send(connection_t *conn, const uint8_t *buf, size_t buflen);

/**
 * Function to check whether IoT Entry sent data.
 */
void
tor_dtls_handle_read(connection_t *conn);

#endif /* TOR_DTLS_H_ */

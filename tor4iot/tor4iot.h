#ifndef TOR4IOT_H_
#define TOR4IOT_H_

#define LOG_MODULE "Tor4IoT"
#define LOG_LEVEL LOG_LEVEL_WARN

//Activate Measurements
#define MEASUREMENT

#include "contiki.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sys/log.h"

#ifdef MEASUREMENT
struct mes_t
{
	uint8_t type;
	clock_time_t clock_time;
	rtimer_clock_t timer_time;
};

#define MESLEN 30

struct mes_t measurements[MESLEN];

uint8_t mes_cnt;
#define TORMES_INIT() mes_cnt = 0
#define TORMES_LOG(t) measurements[mes_cnt].type = (uint8_t)t; measurements[mes_cnt].clock_time = clock_time(); measurements[mes_cnt].timer_time = RTIMER_NOW(); mes_cnt++; if (mes_cnt > MESLEN) {printf("Too many measurements!!\n"); mes_cnt=0;}
#define TORMES_ADD(t, clock, timer) measurements[mes_cnt].type = (uint8_t)t; measurements[mes_cnt].clock_time = clock; measurements[mes_cnt].timer_time = timer; mes_cnt++; if (mes_cnt > MESLEN) {printf("Too many measurements!!\n"); mes_cnt=0;}
#define TORMES_OUT()  for (uint8_t mes_out=0; mes_out < mes_cnt; mes_out++) { \
                        printf("%d:%"PRIu64":%"PRIu64"\n", measurements[mes_out].type, (uint64_t)measurements[mes_out].clock_time, (uint64_t)measurements[mes_out].timer_time); \
                      } \
		      mes_cnt = 0
#define TORMES_SYNC() printf("SYNC:%"PRIu64":%"PRIu64"\nTIMERCONST:%d:%d\nSIZEOF:%d:%d\n", (uint64_t)clock_time(), (uint64_t)RTIMER_NOW(), CLOCK_SECOND, RTIMER_SECOND, sizeof(uint64_t), sizeof(rtimer_clock_t))
#define TORMES_DONE() printf("DONE\n")
#else
#define TORMES_INIT() ((void)0)
#define TORMES_LOG(t) ((void)0)
#define TORMES_ADD(t, clock, timer) ((void)0)
#define TORMES_OUT() ((void)0)
#define TORMES_SYNC() ((void)0)
#define TORMES_DONE() ((void)0)
#endif

#define MES_TYPE_START             0      /** < */
#define MES_TYPE_CONNECTED         1      /** < */
#define MES_TYPE_NTOR1BEGIN        2      /** < NOT USED */
#define MES_TYPE_C25519BEGIN       3      /** < NOT USED */
#define MES_TYPE_C25519END         4      /** < NOT USED */
#define MES_TYPE_NTOR1END          5      /** < NOT USED */
#define MES_TYPE_NTOR2BEGIN        6      /** < NOT USED */
#define MES_TYPE_NTOR2END          7      /** < NOT USED */
#define MES_TYPE_CIRCFINISH        8      /** < NOT USED */

#define MES_TYPE_GOTTICKET         9      /** < Device received ticket */
#define MES_TYPE_CHECKEDTICKET    10      /** < HMAC check of ticket succeeded */
#define MES_TYPE_DECRYPTEDTICKET  11      /** < Ticket decrypted */
#define MES_TYPE_CIRCUITINIT      12      /** < Circuit initialized */
#define MES_TYPE_SENTJOIN         13      /** < NOT USED */
#define MES_TYPE_RECSTREAM        14      /** < RELAY_BEGIN received */
#define MES_TYPE_RECREQUEST       15      /** < PAYLOAD request received */

#define MES_TYPE_TICKETRELAYED    16      /** < ticket relayed message sent */
#define MES_TYPE_RESSTREAM		  17      /** < RELAY_CONNECTED sent */
#define MES_TYPE_RESREQUEST       18      /** < PAYLOAD response sent */

#define MES_TYPE_REQSTREAM        19
#define MES_TYPE_STREAMDONE       20

#define MES_TYPE_RESREQUESTSENT   21
#define MES_TYPE_RESREQUESTDONE   22


#define MES_TYPE_DTLSRECEIVED_TICKET			23
#define MES_TYPE_DTLSSENT_TICKETACK				24

#define MES_TYPE_DTLSRECEIVED_RELAYBEGIN		25
#define MES_TYPE_DTLSSENT_RELAYCONNECTED		26
#define MES_TYPE_DTLSRECEIVED_PAYLOADREQUEST	27
#define MES_TYPE_DTLSSENT_PAYLOADRESPONSE		28

#define MES_TYPE_DTLSSENT_RELAYBEGIN			29
#define MES_TYPE_DTLSRECEIVED_RELAYCONNECTED	30
#define MES_TYPE_DTLSSENT_PAYLOADREQUEST		31
#define MES_TYPE_DTLSRECEIVED_PAYLOADRESPONSE	32

#define MES_TYPE_REND1SENT						33
#define MES_TYPE_DTLSSENT_REND1					34

#define MES_TYPE_DTLSSENT_JOIN					35

#define MES_TYPE_CRYPT_CELL_START				36
#define MES_TYPE_CRYPT_CELL_FINISH				37
#define MES_TYPE_DIGEST_CELL_START				38
#define MES_TYPE_DIGEST_CELL_FINISH				39

#define MES_TYPE_INIT_LASTHOP_HS			    40      /** < Circuit initialized */

#define MES_TYPE_DONE            100      /** < NOT USED */

/* Minimum and maximum values a `signed int' can hold.  */
#undef INT_MIN
#define INT_MIN (-INT_MAX - 1)
#undef INT_MAX
#define INT_MAX __INT_MAX__

#ifdef __GNUC__
/** STMT_BEGIN and STMT_END are used to wrap blocks inside macros so that
 * the macro can be used as if it were a single C statement. */
#define STMT_BEGIN (void) ({
#define STMT_END })
#elif defined(sun) || defined(__sun__)
#define STMT_BEGIN if (1) {
#define STMT_END } else STMT_NIL
#else
#define STMT_BEGIN do {
#define STMT_END } while (0)
#endif /* defined(__GNUC__) || ... */

/** Convenience macro: copy <b>len</b> bytes from <b>inp</b> to <b>ptr</b>,
 * and advance <b>ptr</b> by the number of bytes copied. */
#define APPEND(ptr, inp, len)                   \
  STMT_BEGIN {                                  \
    memcpy(ptr, (inp), (len));                  \
    ptr += len;                                 \
  } STMT_END

#define CELL_DIRECTION_IN  0
#define CELL_DIRECTION_OUT 1

/**
 * Our malloc that ensures that no null is returned.
 */
void *
tor4iot_malloc(size_t size);

/**
 * Our free.
 */
void
tor4iot_free(void* ptr);

typedef struct connection_t connection_t;

/**
 * Called by our DTLS Wrapper when the connection to the IoT Entry is
 * established.
 */
void
handle_connected(connection_t *conn);

typedef struct circuit_t circuit_t;

/** Called by our Circuit module when a response is sent.*/
void
handle_response_sent(circuit_t *circ);

/** Called by our Circuit module when a circuit is established.*/
void
handle_circuit_established(circuit_t *circ);

/*** LENGTHS ***/
#define KEY_LEN 16
#define DIGEST_LEN 20
#define DIGEST256_LEN 32
#define CPATH_KEY_MATERIAL_LEN (20*2+16*2)
#define IOT_ID_LEN 32
#define COOKIE_LEN 4

/** Length of hex encoding of SHA1 digest, not including final NUL. */
#define HEX_DIGEST_LEN 40
/** Length of longest allowable configured nickname. */
#define MAX_NICKNAME_LEN 19

/** Length of our symmetric cipher's keys of 256-bit. */
#define CIPHER256_KEY_LEN 32

/* Output length of KDF for key expansion */
#define HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN \
  (DIGEST256_LEN*2 + CIPHER256_KEY_LEN*2)

/** Length of a curve25519 public key when encoded. */
#define CURVE25519_PUBKEY_LEN 32
/** Length of a curve25519 secret key when encoded. */
#define CURVE25519_SECKEY_LEN 32
/** Length of the result of a curve25519 handshake. */
#define CURVE25519_OUTPUT_LEN 32

/*** CELLS ***/

#define CELL_PAYLOAD_SIZE 509

/* Cell commands.  These values are defined in tor-spec.txt. */
#define CELL_PADDING 0
#define CELL_CREATE 1
#define CELL_CREATED 2
#define CELL_RELAY 3
#define CELL_DESTROY 4
#define CELL_CREATE_FAST 5
#define CELL_CREATED_FAST 6
#define CELL_VERSIONS 7
#define CELL_NETINFO 8
#define CELL_RELAY_EARLY 9
#define CELL_CREATE2 10
#define CELL_CREATED2 11
#define CELL_PADDING_NEGOTIATE 12

#define CELL_IOT_TICKET_RELAYED 21
#define CELL_IOT_FAST_TICKET_RELAYED 23

#define CELL_VPADDING 128
#define CELL_CERTS 129
#define CELL_AUTH_CHALLENGE 130
#define CELL_AUTHENTICATE 131
#define CELL_AUTHORIZE 132

//IOT
#define CELL_JOIN 133
#define CELL_IOT_INFO 134
#define CELL_IOT_PRE_TICKET 135
#define CELL_IOT_TICKET 136
#define CELL_IOT_FAST_TICKET 137

#define CELL_ACK 140


/** True iff the cell command <b>command</b> is one that implies a
 * variable-length cell in Tor link protocol <b>linkproto</b>. */
static inline int
cell_command_is_var_length(uint8_t command)
{
    /* In link protocol version 3 and later, and in version "unknown",
     * commands 128 and higher indicate variable-length. VERSIONS is
     * grandfathered in. */
    return command == CELL_VERSIONS || command >= 128;
}


#define RELAY_BEGIN     1
#define RELAY_DATA      2
#define RELAY_END       3
#define RELAY_CONNECTED 4
#define RELAY_SENDME    5
#define RELAY_EXTEND    6
#define RELAY_EXTENDED  7
#define RELAY_TRUNCATE  8
#define RELAY_TRUNCATED 9
#define RELAY_DROP      10
#define RELAY_RESOLVE   11
#define RELAY_RESOLVED  12
#define RELAY_BEGIN_DIR 13
#define RELAY_EXTEND2   14
#define RELAY_EXTENDED2 15

#define RELAY_ESTABLISH_INTRO 32
#define RELAY_ESTABLISH_RENDEZVOUS 33
#define RELAY_INTRODUCE1 34
#define RELAY_INTRODUCE2 35
#define RELAY_RENDEZVOUS1 36
#define RELAY_RENDEZVOUS2 37
#define RELAY_INTRO_ESTABLISHED 38
#define RELAY_RENDEZVOUS_ESTABLISHED 39
#define RELAY_INTRODUCE_ACK 40

#define RELAY_PRE_TICKET1 50
#define RELAY_PRE_TICKET2 51

#define RELAY_TICKET1 53
#define RELAY_TICKET2 54

#define RELAY_FAST_TICKET1 55
#define RELAY_FAST_TICKET2 56

#define RELAY_TICKET_RELAYED1 57
#define RELAY_TICKET_RELAYED2 58

#define RELAY_FAST_TICKET_RELAYED1 59
#define RELAY_FAST_TICKET_RELAYED2 60

#define CELL_HEADER_SIZE 5 + 2

/** Parsed onion routing cell.  All communication between nodes
 * is via cells. */
typedef struct cell_t {
	uint32_t circ_id; /**< Circuit which received the cell. */
	uint8_t command; /**< Type of the cell: one of CELL_PADDING, CELL_CREATE,
	 * CELL_DESTROY, etc */
	uint16_t cell_num;
	uint8_t payload[CELL_PAYLOAD_SIZE]; /**< Cell body. */
}__attribute__ ((packed)) cell_t;

#define VAR_CELL_HEADER_SIZE 7 + 2

/** Parsed variable-length onion routing cell. */
typedef struct var_cell_t {
	/** Circuit thich received the cell */
	uint32_t circ_id;
	/** Type of the cell: CELL_VERSIONS, etc. */
	uint8_t command;
	uint16_t cell_num;
	/** Number of bytes actually stored in <b>payload</b> */
	uint16_t payload_len;
	/** Payload of this cell */
	uint8_t payload[CELL_PAYLOAD_SIZE
			- (VAR_CELL_HEADER_SIZE - CELL_HEADER_SIZE)];
}__attribute__ ((packed)) var_cell_t;

#define CREATE_CELL_HEADER_SIZE 4

/** A parsed CREATE, CREATE_FAST, or CREATE2 cell. */
typedef struct create_cell_t {
	/** One of the ONION_HANDSHAKE_TYPE_* values */
	uint16_t handshake_type;
	/** The number of bytes used in <b>onionskin</b>. */
	uint16_t handshake_len;
	/** The client-side message for the circuit creation handshake. */
	uint8_t onionskin[CELL_PAYLOAD_SIZE - CREATE_CELL_HEADER_SIZE];
}__attribute__ ((packed)) create_cell_t;

#define CREATED_CELL_HEADER_SIZE 2

/** A parsed CREATED, CREATED_FAST, or CREATED2 cell. */
typedef struct created_cell_t {
	/** The number of bytes used in <b>reply</b>. */
	uint16_t handshake_len;
	/** The server-side message for the circuit creation handshake. */
	uint8_t reply[CELL_PAYLOAD_SIZE - CREATED_CELL_HEADER_SIZE];
}__attribute__ ((packed)) created_cell_t;

#define RELAY_CELL_HEADER_SIZE 11
#define RELAY_CELL_PAYLOAD_SIZE CELL_PAYLOAD_SIZE - RELAY_CELL_HEADER_SIZE

/**
 * Relay cell header and payload.
 */
typedef struct relay_cell_t {
	uint8_t relay_command;
	uint16_t recognized;
	uint16_t stream_id;
	uint8_t digest[4];
	uint16_t payload_len;
	uint8_t payload[CELL_PAYLOAD_SIZE - RELAY_CELL_HEADER_SIZE];
}__attribute__ ((packed)) relay_cell_t;

#define EXTEND_CELL_HEADER_SIZE 11 + DIGEST_LEN

/** A parsed RELAY_EXTEND or RELAY_EXTEND2 cell */
typedef struct extend_cell_t {
	uint8_t link_spec_num;

	// We hardcode IPv4 specs || lstype == 0x00
	uint8_t lstype_ip;
	uint8_t lslen_ip;
	uint8_t lspec_ip_ip[4];
	uint16_t lspec_port_ip;

	// We hardcode RSA ID specs || lstype == 0x02
	uint8_t lstype_id;
	uint8_t lslen_id;
	uint8_t rsa_id[DIGEST_LEN];

	/** The "create cell" embedded in this extend cell. Note that unlike the
	 * create cells we generate ourself, this once can have a handshake type we
	 * don't recognize. */
	create_cell_t create_cell;
}__attribute__ ((packed)) extend_cell_t;

/** A parsed RELAY_EXTEND or RELAY_EXTEND2 cell */
typedef struct extended_cell_t {
	/** The "created cell" embedded in this extended cell. */
	created_cell_t created_cell;
}__attribute__ ((packed)) extended_cell_t;

/**
 * Struct for encryption and decryption information, i.e., AES key and already
 * crypted bytes.
 */
typedef struct iot_crypto_aes_t {
	uint8_t aes_key[16];
	uint16_t crypted_bytes;
}__attribute__ ((packed)) iot_crypto_aes_t;

/**
 * Structure combining sending and receiving direction crypto for a relay. Used
 * inside the ticket representation.
 */
typedef struct iot_crypto_aes_relay_t {
	iot_crypto_aes_t f;
	iot_crypto_aes_t b;
}__attribute__ ((packed)) iot_crypto_aes_relay_t;

#define IOT_TICKET_NONCE_LEN 16

/**
 * Representation of the ticket sent by the DHS
 */
typedef struct iot_ticket_t {
	uint8_t nonce[IOT_TICKET_NONCE_LEN];

	uint32_t cookie;

	uint8_t type;
#define IOT_TICKET_TYPE_HS 1
#define IOT_TICKET_TYPE_CLIENT 2

	iot_crypto_aes_relay_t entry;
	iot_crypto_aes_relay_t relay1;
	iot_crypto_aes_relay_t relay2;
	iot_crypto_aes_relay_t rend;

	uint8_t f_rend_init_digest[DIGEST_LEN];

	uint8_t hs_ntor_key[HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN];

#define HSv3_REND_INFO 84

    uint8_t rend_info[HSv3_REND_INFO];

	uint8_t mac[DIGEST256_LEN];
}__attribute__ ((packed)) iot_ticket_t;

/**
 * Representation of the fast ticket sent by the client when no DHS is used
 */
 typedef struct iot_fast_ticket_t {
   uint8_t nonce[IOT_TICKET_NONCE_LEN];

   uint32_t cookie;

   uint8_t hs_ntor_key[HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN];

   uint8_t mac[DIGEST256_LEN];
 }__attribute__ ((packed)) iot_fast_ticket_t;

/**
 * Buffer for incoming and outgoing cells
 */
uint8_t buffer[CELL_HEADER_SIZE + CELL_PAYLOAD_SIZE];

#endif /* TOR4IOT_H_ */

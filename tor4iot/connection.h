#ifndef CONNECTION_H_
#define CONNECTION_H_

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/udp-socket.h"

#include "tinydtls.h"

typedef struct ntor_handshake_state_t ntor_handshake_state_t;

/**
 * Connection representation including DTLS session, DTLS context, UDP connection,
 * and cell nums.
 */
typedef struct connection_t {
	session_t session;
	dtls_context_t *ctx;
	struct uip_udp_conn *udp_conn;

	uint8_t already_connected;

	uint16_t cell_num_out;
	uint16_t cell_num_in;
} connection_t;

typedef struct circuit_t circuit_t;

/**
 * Instruct the DTLS module to establish a connection to the IoT Entry.
 */
int
connect_to_or(connection_t* conn, const uint16_t *ip, int port);

int
disconnect_from_or(connection_t *conn);

/**
 * Write some bytes to the IoT Entry.
 */
int
write_to_or(connection_t* conn, const void* buf, size_t len);

/**
 * Send a cell to the IoT Entry. Sets the cell num correspondingly.
 */
int
conn_send_cell(connection_t* conn, const void *buf);

/**
 * Send a var_cell to the IoT Entry. Sets the cell num correspondingly.
 */
int
conn_send_var_cell(connection_t* conn, const void *buf, size_t len);

/**
 * Handle an incoming cell.
 */
void
conn_handle_input(connection_t* conn, uint8_t *buf, size_t len);

#endif /* CONNECTION_H_ */

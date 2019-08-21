#ifndef CIRCUIT_H_
#define CIRCUIT_H_

#include "connection.h"
#include "tor_crypto.h"

#define SERVICE_SIDE 1
#define CLIENT_SIDE 2

#define CPATH_KEY_MATERIAL_LEN (20*2+16*2)

/**
 * Used for Tor@IoT in order to add nodes to circuits using data from the
 * consensus.
 */
struct tor_node_raw {
	const uint8_t* ip4;
	const uint16_t* ip6;
	const uint16_t port;
};

/**
 * Double linked list of nodes contained in our circuit.
 */
typedef struct circuit_member_t {
	uint8_t head :1;
	uint8_t tail :1;

	uint8_t established :1;

	t4i_aes_ctx forward_aes;
	t4i_aes_ctx backward_aes;

	t4i_mac_ctx forward_mac;
	t4i_mac_ctx backward_mac;

	struct circuit_member_t* next;
	struct circuit_member_t* previous;
} circuit_member_t;

/**
 * Circuit representation.
 */
typedef struct circuit_t {
	uint32_t circ_id;
	circuit_member_t* head;
	circuit_member_t* tail;
	connection_t* conn;

	ntor_handshake_state_t *state;
} circuit_t;

circuit_t circ_no_1;

circuit_member_t circ_mem_no_1;
circuit_member_t circ_mem_no_2;
circuit_member_t circ_mem_no_3;
circuit_member_t circ_mem_no_4;
circuit_member_t circ_mem_no_5;

/**
 * Send a var cell over a given circuit. Encrypt it correspondingly.
 */
void
circuit_send_var_cell(circuit_t* circ, var_cell_t* var_cell);

/**
 * Send a cell over a given circuit. Encrypt it correspondingly.
 */
void
circuit_send_cell(circuit_t* circ, cell_t* cell, uint8_t mestype);

/**
 * Handle incoming cell.
 */
void
circuit_handle_cell(circuit_t* circ, cell_t *cell);

/**
 * Initialize a circuit representation on a connection.
 */
void
circuit_init(circuit_t *circ, connection_t *conn, uint32_t id);

/**
 * Add a new member to the end of a circuit.
 */
void
circuit_add_member(circuit_t *circ, circuit_member_t *member);

/**
 * Add a new member to the end of a circuit by crypto material, e.g., from ticket.
 */
void
circuit_add_member_by_material(circuit_t *circ, circuit_member_t *new,
		iot_crypto_aes_relay_t *material, uint8_t side);

/**
 * Initialize a circuit using a ticket.
 */
void
circuit_process_ticket(circuit_t *circ, iot_ticket_t *ticket);

void
circuit_process_fast_ticket(circuit_t *circ, iot_fast_ticket_t *ticket);

/**
 * Close a circuit.
 */
void
circuit_close(circuit_t *circ);

#endif /* CIRCUIT_H_ */

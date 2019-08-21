#include "tor4iot.h"
#include "circuit.h"
#include "tor_crypto.h"
#include "tor_util_format.h"
#include "tinydtls.h"

static void crypt_cell(circuit_t* circ, cell_t* cell, uint8_t direction) {
	circuit_member_t *node, *last_node;
	static uint8_t their_digest[4], our_digest[4];
	static uint8_t computed_digest;
	int res;

	last_node = 0;
	computed_digest = 0;

	TORMES_LOG(MES_TYPE_CRYPT_CELL_START);

	if (!circ->head->established) {
		LOG_DBG("Head of circuit not established. Skipping de-/encryption.\n");
		return;
	}

	if (direction == CELL_DIRECTION_IN) {
		node = circ->head;
	} else {
		node = circ->tail;
	}

	while (node) {
		if (direction == CELL_DIRECTION_IN) {
			if (node->established) {
				LOG_DBG("Decrypting cell for node %p\n", node);
				tor4iot_aes_crypt(&node->backward_aes, cell->payload,
				CELL_PAYLOAD_SIZE, 0);
				last_node = node;
			}
			node = node->next;
		} else {
			if (node->established) {
				if (!computed_digest) {
					LOG_DBG("Add digest in cell for node %p\n", node);
					TORMES_LOG(MES_TYPE_DIGEST_CELL_START);
					memset(((relay_cell_t*) cell->payload)->digest, 0, 4);
					tor4iot_intermediate_mac(&node->forward_mac, cell->payload,
					CELL_PAYLOAD_SIZE, ((relay_cell_t*) cell->payload)->digest,
							4);
					computed_digest = 1;
					TORMES_LOG(MES_TYPE_DIGEST_CELL_FINISH);
				}
				LOG_DBG("Encrypting cell for node %p\n", node);
				tor4iot_aes_crypt(&node->forward_aes, cell->payload,
				CELL_PAYLOAD_SIZE, 0);
			}
			node = node->previous;
		}
	}

	if (direction == CELL_DIRECTION_IN) {
		if (last_node) {
			TORMES_LOG(MES_TYPE_DIGEST_CELL_START);
			memcpy(their_digest, ((relay_cell_t*) cell->payload)->digest, 4);
			memset(((relay_cell_t*) cell->payload)->digest, 0, 4);

			tor4iot_intermediate_mac(&last_node->backward_mac, cell->payload,
			CELL_PAYLOAD_SIZE, our_digest, 4);

			res = memcmp(our_digest, their_digest, 4);
			if (res) {
				LOG_INFO("Digest check failed!\n");
			}
			TORMES_LOG(MES_TYPE_DIGEST_CELL_FINISH);
		}
	}

	TORMES_LOG(MES_TYPE_CRYPT_CELL_FINISH);
}

void circuit_send_var_cell(circuit_t* circ, var_cell_t* var_cell) {
	var_cell->circ_id = uip_htonl(circ->circ_id);

	conn_send_var_cell(circ->conn, var_cell, uip_ntohs(var_cell->payload_len));
}

void circuit_send_cell(circuit_t* circ, cell_t* cell, uint8_t mestype) {
	LOG_DBG("Sending cell %p with command %d on circuit %"PRIu32"\n", cell, cell->command,
			circ->circ_id);
	cell->circ_id = uip_htonl(circ->circ_id);

	crypt_cell(circ, cell, CELL_DIRECTION_OUT);

	if (mestype) {
		TORMES_LOG(mestype);
	}
	conn_send_cell(circ->conn, cell);
}

const uint8_t hs_ip[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

void circuit_handle_cell(circuit_t *circ, cell_t *cell) {
	relay_cell_t *relay_cell;

	if (uip_ntohl(cell->circ_id) != circ->circ_id) {
		LOG_INFO("Circ ID mismatch (cell: %lu, expected: %lu). Dropped cell.\n", uip_ntohl(cell->circ_id), circ->circ_id);
		return;
	}

	switch (cell->command) {
	case CELL_DESTROY:
		LOG_INFO("Circuit %"PRIu32" destroyed by Tor node.\n", circ->circ_id);

		handle_response_sent(circ);
		break;
	case CELL_RELAY:
	case CELL_RELAY_EARLY:

		crypt_cell(circ, cell, CELL_DIRECTION_IN);

		relay_cell = (relay_cell_t*) cell->payload;

		LOG_DBG("Relay cell with command %d, recognized %d, stream id %d, and"
				"length %d.\n", relay_cell->relay_command,
				uip_ntohs(relay_cell->recognized),
				uip_ntohs(relay_cell->stream_id),
				uip_ntohs(relay_cell->payload_len));

		switch (relay_cell->relay_command) {
		case RELAY_BEGIN:
			TORMES_ADD(MES_TYPE_DTLSRECEIVED_RELAYBEGIN, mes_dtls_clock_received, mes_dtls_timer_received);
			TORMES_LOG(MES_TYPE_RECSTREAM);

			relay_cell->relay_command = RELAY_CONNECTED;
			relay_cell->payload_len = uip_htons(25);
			memset(relay_cell->payload, 0, RELAY_CELL_PAYLOAD_SIZE);

			struct relay_connected_payload {
				uint32_t zero_valued;
				uint8_t addr_type;
				uint8_t addr[16];
				uint32_t ttl;
			};

			struct relay_connected_payload *connected =
					(struct relay_connected_payload*) relay_cell->payload;

			connected->addr_type = 6;

			memcpy(connected->addr, hs_ip, 16);

			connected->ttl = uip_htonl(255);

			cell->command = CELL_RELAY;

			circuit_send_cell(circ, cell, MES_TYPE_RESSTREAM);
			TORMES_ADD(MES_TYPE_DTLSSENT_RELAYCONNECTED, mes_dtls_clock_sent, mes_dtls_timer_sent);

			break;

		case RELAY_CONNECTED:
			LOG_DBG("\n\nTor connection to service established.\n");
			LOG_DBG("Sending request\n");

			TORMES_LOG(MES_TYPE_STREAMDONE);
			TORMES_ADD(MES_TYPE_DTLSRECEIVED_RELAYCONNECTED, mes_dtls_clock_received, mes_dtls_timer_received);

#define DST_HOST "handover.iot"
#define DST_PATH "/"

			const char* http_request = "GET " DST_PATH " HTTP/1.0\r\nHost: " DST_HOST "\r\n\r\n";
			LOG_DBG("\n%s\n", http_request);

			relay_cell->relay_command = RELAY_DATA;
			relay_cell->payload_len = uip_htons(25);
			memset(relay_cell->payload, 0, RELAY_CELL_PAYLOAD_SIZE);

			sprintf((char *) relay_cell->payload, "%s", http_request);
			relay_cell->payload_len = uip_htons(
					strlen((char *) relay_cell->payload) + 1);

			LOG_DBG("Sending a cell for circuit %"PRIu32", command %d.\n",
					uip_ntohl(cell->circ_id), cell->command);
			LOG_DBG("Relay cell with command %d, recognized %d, stream id %d,"
					"and length %d.\n", relay_cell->relay_command,
					uip_ntohs(relay_cell->recognized),
					uip_ntohs(relay_cell->stream_id),
					uip_ntohs(relay_cell->payload_len));

			cell->command = CELL_RELAY;

			circuit_send_cell(circ, cell, MES_TYPE_RESREQUESTSENT);
			TORMES_ADD(MES_TYPE_DTLSSENT_PAYLOADREQUEST, mes_dtls_clock_sent, mes_dtls_timer_sent);

			break;

		case RELAY_DATA:

			LOG_DBG("\n\nWe received payload data:\n");
			LOG_DBG_("%s\n", relay_cell->payload);

			if (!strncmp((char *) relay_cell->payload, "GET", 3)) {
				TORMES_LOG(MES_TYPE_RECREQUEST);
				TORMES_ADD(MES_TYPE_DTLSRECEIVED_PAYLOADREQUEST, mes_dtls_clock_received, mes_dtls_timer_received);

				// We received a GET request - Answer it.
				const char *response = "HTTP/1.1 200 OK\n"
						"Server:Tor4IoT\n"
						"Accept-Ranges: bytes\n"
						"Content-Length: 36\n"
						"Content-Type: text/html\n\n"
						"<html><body>THANK YOU!</body></html>";
				LOG_DBG("Returning: %s\n", response);

				sprintf((char *) relay_cell->payload, "%s", response);
				relay_cell->payload_len = uip_htons(
						strlen((char *) relay_cell->payload) + 1);

				LOG_DBG("Sending a cell for circuit %"PRIu32", command %d.\n",
						uip_ntohl(cell->circ_id), cell->command);
				LOG_DBG("Relay cell with command %d, recognized %d, stream id %d,"
						"and length %d.\n", relay_cell->relay_command,
						uip_ntohs(relay_cell->recognized),
						uip_ntohs(relay_cell->stream_id),
						uip_ntohs(relay_cell->payload_len));

				cell->command = CELL_RELAY;
				circuit_send_cell(circ, cell, MES_TYPE_RESREQUEST);
				TORMES_ADD(MES_TYPE_DTLSSENT_PAYLOADRESPONSE, mes_dtls_clock_sent, mes_dtls_timer_sent);

			} else {
				LOG_DBG("Was an answer. Closing circuit.\n");

				TORMES_LOG(MES_TYPE_RESREQUESTDONE);
				TORMES_ADD(MES_TYPE_DTLSRECEIVED_PAYLOADRESPONSE, mes_dtls_clock_received, mes_dtls_timer_received);

				memset(cell->payload, 0, sizeof(cell_t));
				cell->command = CELL_DESTROY;
				conn_send_cell(circ->conn, cell);
			}

			handle_response_sent(circ);

			break;

		case RELAY_END:
			LOG_INFO("The client closed the connection.\n");
			return;
		default:
			LOG_INFO("Unknown command.\n");
			return;
		}

		break;
	case CELL_CREATED:
		LOG_DBG("Created cell received!\n");
		break;
	}

}

void circuit_init(circuit_t *circ, connection_t *conn, uint32_t id) {
	memset(circ, 0, sizeof(circuit_t));

	circ->conn = conn;
	circ->circ_id = id;
}

void circuit_add_member(circuit_t *circ, circuit_member_t *member) {
	circuit_member_t* last_member;

	if (circ->head == 0) {
		circ->head = member;
		circ->tail = member;
		member->head = 1;
		member->tail = 1;

		member->next = 0;
		member->previous = 0;
	} else {
		last_member = circ->tail;

		last_member->next = member;
		member->previous = last_member;

		last_member->tail = 0;
		member->tail = 1;

		member->head = 0;
		member->next = 0;

		circ->tail = member;
	}

	member->established = 0;
}

static const uint8_t zero_iv[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };

void init_crypto_direction(t4i_aes_ctx *ctx, iot_crypto_aes_t *direction_info) {
	uint8_t dev_null[CELL_PAYLOAD_SIZE];
	int data_len = CELL_PAYLOAD_SIZE;

	LOG_DBG("Initializing crypto context %p with info %p\n", ctx,
			direction_info);

	tor4iot_aes_init(ctx, direction_info->aes_key, 16, zero_iv);

	int cell_ctr = uip_ntohs(direction_info->crypted_bytes) / 509;

	LOG_DBG(
			"Delegation server utilized this key for %d cells (%d bytes) already."
					"Doing the same.\n", cell_ctr,
			uip_ntohs(direction_info->crypted_bytes));

	for (int i = 0; i < cell_ctr; i++) {
		tor4iot_aes_crypt(ctx, dev_null, data_len, 1);
	}
}

void circuit_add_member_by_material(circuit_t *circ, circuit_member_t *new,
		iot_crypto_aes_relay_t *material, uint8_t side) {
	memset(new, 0, sizeof(circuit_member_t));

	circuit_add_member(circ, new);

	LOG_DBG("Initializing member %p using material %p\n", new, material);
    LOG_DBG("Initializing forward first...\n");
    init_crypto_direction(&new->forward_aes, &material->f);
    init_crypto_direction(&new->backward_aes, &material->b);

	new->established = 1;
}

void circuit_add_hsv3_by_material(circuit_t *circ, circuit_member_t *new,
		uint8_t *material, uint8_t side) {
	memset(new, 0, sizeof(circuit_member_t));

	circuit_add_member(circ, new);

	LOG_DBG("Initializing hsv3 member %p using material %p\n", circ, material);

	new->backward_mac.type = keccak;
	new->forward_mac.type = keccak;

	tor4iot_init_mac(&new->backward_mac);
	tor4iot_init_mac(&new->forward_mac);

	switch (side) {
	case SERVICE_SIDE:
                LOG_DBG("Initializing backward first...\n");
		tor4iot_update_mac(&new->backward_mac, material, 32);
		tor4iot_update_mac(&new->forward_mac, material + 32, 32);

		tor4iot_aes_init(&new->backward_aes, material + 2 * 32, 32, zero_iv);
		tor4iot_aes_init(&new->forward_aes, material + 3 * 32, 32, zero_iv);
		break;
	case CLIENT_SIDE:
                LOG_DBG("Initializing forward first...\n");
		tor4iot_update_mac(&new->forward_mac, material, 32);
		tor4iot_update_mac(&new->backward_mac, material + 32, 32);

		tor4iot_aes_init(&new->forward_aes, material + 2 * 32, 32, zero_iv);
		tor4iot_aes_init(&new->backward_aes, material + 3 * 32, 32, zero_iv);
		break;
	}

	new->established = 1;
}

void circuit_process_ticket(circuit_t *circ, iot_ticket_t *ticket) {
	uint8_t buffer[CELL_HEADER_SIZE + CELL_PAYLOAD_SIZE];

	LOG_DBG("Init circ members using ticket...\n");

	if (ticket->type == IOT_TICKET_TYPE_CLIENT) {
		circuit_add_member_by_material(circ, &circ_mem_no_1, &ticket->entry, CLIENT_SIDE);
		circuit_add_member_by_material(circ, &circ_mem_no_2, &ticket->relay1, CLIENT_SIDE);
		circuit_add_member_by_material(circ, &circ_mem_no_3, &ticket->relay2, CLIENT_SIDE);
		circuit_add_member_by_material(circ, &circ_mem_no_4, &ticket->rend, CLIENT_SIDE);

		circuit_add_hsv3_by_material(circ, &circ_mem_no_5, ticket->hs_ntor_key, CLIENT_SIDE);
	} else {
		circuit_add_member_by_material(circ, &circ_mem_no_1, &ticket->entry, SERVICE_SIDE);
		circuit_add_member_by_material(circ, &circ_mem_no_2, &ticket->relay1, SERVICE_SIDE);
		circuit_add_member_by_material(circ, &circ_mem_no_3, &ticket->relay2, SERVICE_SIDE);
		circuit_add_member_by_material(circ, &circ_mem_no_4, &ticket->rend, SERVICE_SIDE);

		//Additionally we need to initialize digest for rend in forward direction
		circ_mem_no_4.forward_mac.type = sha1;

		tor4iot_init_mac(&circ_mem_no_4.forward_mac);
		tor4iot_update_mac(&circ_mem_no_4.forward_mac, ticket->f_rend_init_digest, DIGEST_LEN);
	}

	TORMES_LOG(MES_TYPE_CIRCUITINIT);

	LOG_DBG("Send JOIN request to SP...\n");

	var_cell_t *var_cell = (var_cell_t *)buffer;

	var_cell->circ_id = uip_htonl(circ->circ_id);
	var_cell->command = CELL_JOIN;
	memcpy(var_cell->payload, &ticket->cookie, COOKIE_LEN);
	var_cell->payload_len = uip_htons(COOKIE_LEN);

	TORMES_LOG(MES_TYPE_SENTJOIN);
	conn_send_var_cell(circ->conn, var_cell, COOKIE_LEN);

	cell_t *cell = (cell_t *)buffer;
	relay_cell_t *relay_cell = (relay_cell_t *) cell->payload;

	TORMES_ADD(MES_TYPE_DTLSSENT_JOIN, mes_dtls_clock_sent, mes_dtls_timer_sent);

	switch (ticket->type) {
	case IOT_TICKET_TYPE_HS:

		//Send RENDEZVOUS1 cell

		relay_cell->relay_command = RELAY_RENDEZVOUS1;
		relay_cell->recognized = 0;
		relay_cell->stream_id = uip_htons(0);
		relay_cell->payload_len = uip_htons(168);

		memcpy(relay_cell->payload, ticket->rend_info, HSv3_REND_INFO);
		compute_random(relay_cell->payload + HSv3_REND_INFO, 168 - HSv3_REND_INFO);

		cell->command = CELL_RELAY;

		circuit_send_cell(circ, cell, MES_TYPE_REND1SENT);
		TORMES_ADD(MES_TYPE_DTLSSENT_REND1, mes_dtls_clock_sent, mes_dtls_timer_sent);

		circuit_add_hsv3_by_material(circ, &circ_mem_no_5, ticket->hs_ntor_key, SERVICE_SIDE);

		TORMES_LOG(MES_TYPE_INIT_LASTHOP_HS);

		break;
	case IOT_TICKET_TYPE_CLIENT:
		//Send Relay Begin
		relay_cell->relay_command = RELAY_BEGIN;
		relay_cell->recognized = 0;
		relay_cell->stream_id = uip_htons(1234);
		relay_cell->payload_len = uip_htons(0);
		memset(relay_cell->payload, 0, RELAY_CELL_PAYLOAD_SIZE);

		cell->command = CELL_RELAY;

		circuit_send_cell(circ, cell, MES_TYPE_REQSTREAM);

		TORMES_ADD(MES_TYPE_DTLSSENT_RELAYBEGIN, mes_dtls_clock_sent, mes_dtls_timer_sent);

		break;
	default:
		return;
	}
}

void circuit_process_fast_ticket(circuit_t *circ, iot_fast_ticket_t *ticket) {
	unsigned char iot_mac_key2[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                14, 15 };

	LOG_DBG("Sending Tor Ticket relayed to origin...\n");

	cell_t cell;
	memset(cell.payload, 0, CELL_PAYLOAD_SIZE);

	tor4iot_hmac_sha256(cell.payload, iot_mac_key2, 16, ticket->hs_ntor_key,
			HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN);

	LOG_DBG("HMAC: %02x %02x\n", cell.payload[0], cell.payload[1]);

	cell.circ_id = uip_htonl(circ->circ_id);

	cell.command = CELL_IOT_FAST_TICKET_RELAYED;

	TORMES_LOG(MES_TYPE_TICKETRELAYED);
	conn_send_cell(circ->conn, &cell);
	TORMES_ADD(MES_TYPE_DTLSSENT_TICKETACK, mes_dtls_clock_sent, mes_dtls_timer_sent);

	LOG_DBG("Init circ members using ticket...\n");

	circuit_add_hsv3_by_material(circ, &circ_mem_no_5, ticket->hs_ntor_key, SERVICE_SIDE);

	TORMES_LOG(MES_TYPE_CIRCUITINIT);

}

void circuit_close(circuit_t *circ) {
	circuit_member_t *current;
	current = circ->head;

	while (current) {
		current->established = 0;
		current = current->next;
	}
}

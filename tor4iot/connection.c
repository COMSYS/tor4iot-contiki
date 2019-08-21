#include "tor4iot.h"

#include "connection.h"
#include "circuit.h"

#include "tor_dtls.h"
#include "tor_delegation.h"

int connect_to_or(connection_t* conn, const uint16_t* ip, int port) {
	LOG_INFO("Connecting to OR...\n");

	/* Initialize UDP connection */
	uip_ip6addr(&conn->session.addr, ip[0], ip[1], ip[2], ip[3], ip[4], ip[5],
			ip[6], ip[7]);
	conn->session.port = uip_htons(port);

	conn->cell_num_in = 0;
	conn->cell_num_out = 0;

	conn->already_connected = 0;


	LOG_DBG("\nconnect_to_or\n"
			  "Session: %p (size of session_t: %d)\n"
			  "Tor Connection: %p\n"
			  "IP Address (%p): ", &conn->session, sizeof(session_t), conn, &conn->session.addr);
	LOG_DBG_6ADDR(&conn->session.addr);
	LOG_DBG_("\n");

	LOG_INFO("OR Connection Information: ");
	LOG_INFO_6ADDR(&conn->session.addr);
	LOG_INFO_(":%d\n", uip_ntohs(conn->session.port));

	tor_dtls_connect(conn);

	return 0;
}

int disconnect_from_or(connection_t *conn) {
	LOG_INFO("Disconnect\n");

	tor_dtls_disconnect(conn);

	return 0;
}

int write_to_or(connection_t* conn, const void* buf, size_t len) {
	return tor_dtls_send(conn, buf, len);
}

int conn_send_cell(connection_t* conn, const void *buf) {
	cell_t *cell = (cell_t *) buf;

	LOG_DBG("Sending cell %p on connection %p with cellnum %d\n", buf, conn,
			conn->cell_num_out);

	cell->cell_num = uip_htons(conn->cell_num_out);

	conn->cell_num_out++;
	return write_to_or(conn, buf, CELL_HEADER_SIZE + CELL_PAYLOAD_SIZE);
}

int conn_send_var_cell(connection_t* conn, const void *buf, size_t len) {
	var_cell_t *cell = (var_cell_t *) buf;

	cell->cell_num = uip_htons(conn->cell_num_out);
	conn->cell_num_out++;

	return write_to_or(conn, buf, VAR_CELL_HEADER_SIZE + len);
}

void conn_send_ack(connection_t* conn) {
	uint8_t ackbuf[VAR_CELL_HEADER_SIZE];
	memset(ackbuf, 0, VAR_CELL_HEADER_SIZE);

	var_cell_t* ack = (var_cell_t *) ackbuf;

	ack->command = CELL_ACK;
	ack->cell_num = uip_htons(conn->cell_num_in);

	LOG_INFO("Sending ACK with cell num %d\n", conn->cell_num_in);

	write_to_or(conn, ackbuf, VAR_CELL_HEADER_SIZE);
}

uint16_t conn_handle_var_cell(connection_t* conn, uint8_t *buf, size_t len) {
	var_cell_t *cell = (var_cell_t *) buf;
	LOG_INFO("Var cell of length %d with command %d and cell num %d for"
			"circuit %"PRIu32" received.\n", uip_ntohs(cell->payload_len),
			cell->command, uip_ntohs(cell->cell_num),
			uip_ntohl(cell->circ_id));

	if (uip_ntohs(cell->payload_len) > len) {
		LOG_WARN("Received a longer var cell than buffer is available.\n");
	}

	if (cell->command == CELL_ACK) {
		LOG_INFO("ACK received.\n");
	} else if (uip_ntohs(cell->cell_num) == conn->cell_num_in) {
		LOG_INFO("Cell num was ok (%d).\n", conn->cell_num_in);
		conn->cell_num_in++;
		conn_send_ack(conn);
	} else {
		LOG_WARN("Cell with wrong number %d (%d) received. Out of order or"
				"loss detected.\n", uip_ntohs(cell->cell_num),
				conn->cell_num_in);
		conn->cell_num_in = uip_ntohs(cell->cell_num) + 1;
	}

	uint16_t cell_len = uip_ntohs(cell->payload_len) + VAR_CELL_HEADER_SIZE;

	switch(cell->command) {
	case CELL_IOT_TICKET:
		delegation_process_ticket(conn, (iot_ticket_t *)cell->payload);
		break;
	case CELL_IOT_FAST_TICKET:
		delegation_process_fast_ticket(conn, (iot_fast_ticket_t *)cell->payload, uip_ntohl(cell->circ_id));
		break;
	}
	return cell_len;
}

void conn_handle_cell(connection_t* conn, uint8_t *buf) {
	cell_t *cell = (cell_t *) buf;
	LOG_INFO("Cell with command %d for circuit %"PRIu32" received.\n",
			cell->command, uip_ntohl(cell->circ_id));

	if (uip_ntohs(cell->cell_num) == conn->cell_num_in) {
		LOG_INFO("Cell num was ok (%d).\n", conn->cell_num_in);
		conn->cell_num_in++;
		conn_send_ack(conn);
	} else {
		LOG_WARN("Cell with wrong number %d (%d) received. Out of order or"
				"loss detected.\n", uip_ntohs(cell->cell_num),
				conn->cell_num_in);
		conn->cell_num_in = uip_ntohs(cell->cell_num) + 1;
	}

	circuit_handle_cell(&circ_no_1, (cell_t *) buf);
}

void conn_handle_input(connection_t* conn, uint8_t *buf, size_t len) {
	cell_t *cell = (cell_t *) buf;
	uint16_t offset;

        LOG_DBG("Cell has command %d\n", cell->command);

	if (cell_command_is_var_length(cell->command)) {
		offset = conn_handle_var_cell(conn, buf, len);
		if (len - offset > 0) {
			conn_handle_input(conn, buf+offset, len-offset);
		}
	} else {
		conn_handle_cell(conn, buf);
		if (len > CELL_HEADER_SIZE + CELL_PAYLOAD_SIZE) {
			conn_handle_var_cell(conn, buf + (CELL_HEADER_SIZE + CELL_PAYLOAD_SIZE),
					len-(CELL_HEADER_SIZE + CELL_PAYLOAD_SIZE));
		}
	}
}

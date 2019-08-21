#include "tor_delegation.h"
#include "tor_crypto.h"
#include "circuit.h"

/***** KEY INFOS *******/
unsigned char iot_mac_key[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                14, 15 };

unsigned char iot_key[] =
                { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

unsigned char iot_iv[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

#define IOT_MAC_KEY_LEN 16


void delegation_send_info(connection_t *conn, uint8_t *info, size_t infolen) {
	var_cell_t *work_cell = (var_cell_t*) buffer;

	work_cell->circ_id = 0;
	work_cell->command = CELL_IOT_INFO;
	work_cell->payload_len = uip_htons(infolen + 4);
	memcpy(work_cell->payload, info, infolen);

	uint16_t in = uip_htons(conn->cell_num_in);
	uint16_t out = uip_htons(conn->cell_num_out);

	memcpy(work_cell->payload + infolen, &in, 2);
	memcpy(work_cell->payload + infolen + 2, &out, 2);

	conn_send_var_cell(conn, work_cell, infolen + 4);
}

void delegation_process_ticket(connection_t *conn, iot_ticket_t *ticket) {
	DUMP_MEMORY("handoverticket", ticket, sizeof(iot_ticket_t));

	TORMES_ADD(MES_TYPE_DTLSRECEIVED_TICKET, mes_dtls_clock_received, mes_dtls_timer_received);
	TORMES_LOG(MES_TYPE_GOTTICKET);

	//STEP 1: Check HMAC.

	unsigned char buf[DIGEST256_LEN];

	tor4iot_hmac_sha256(buf, iot_mac_key, IOT_MAC_KEY_LEN, ticket,
			sizeof(iot_ticket_t) - DIGEST256_LEN);

	if (memcmp(buf, ticket->mac, DIGEST256_LEN)) {
		LOG_WARN("HMAC Check FAILED!\n");
		return;
	}

	TORMES_LOG(MES_TYPE_CHECKEDTICKET);

	LOG_DBG("HMAC was ok.\n");

	//STEP 2: Decrypt ticket.

	tor4iot_aes_crypt_once(((uint8_t *) ticket) + IOT_TICKET_NONCE_LEN,
			sizeof(iot_ticket_t) - DIGEST256_LEN - IOT_TICKET_NONCE_LEN,
			iot_key, ticket->nonce);

	TORMES_LOG(MES_TYPE_DECRYPTEDTICKET);

	//STEP 3: Hand over ticket to initialized circuit.

	circuit_init(&circ_no_1, conn, 17 + circuit_counter);
	circuit_counter++;
	circuit_process_ticket(&circ_no_1, ticket);

	return;
}

void delegation_process_fast_ticket(connection_t *conn, iot_fast_ticket_t *ticket, uint32_t circ_id) {
    DUMP_MEMORY("extendticket", ticket, sizeof(iot_fast_ticket_t));

	TORMES_ADD(MES_TYPE_DTLSRECEIVED_TICKET, mes_dtls_clock_received, mes_dtls_timer_received);
	TORMES_LOG(MES_TYPE_GOTTICKET);

	//STEP 1: Check HMAC.

	unsigned char buf[DIGEST256_LEN];

	tor4iot_hmac_sha256(buf, iot_mac_key, IOT_MAC_KEY_LEN, ticket,
			sizeof(iot_fast_ticket_t) - DIGEST256_LEN);

	if (memcmp(buf, ticket->mac, DIGEST256_LEN)) {
		LOG_WARN("HMAC Check FAILED!\n");
		return;
	}

	TORMES_LOG(MES_TYPE_CHECKEDTICKET);

	LOG_DBG("HMAC was ok.\n");

	//STEP 2: Decrypt ticket.

	tor4iot_aes_crypt_once(((uint8_t *) ticket) + IOT_TICKET_NONCE_LEN,
			sizeof(iot_fast_ticket_t) - DIGEST256_LEN - IOT_TICKET_NONCE_LEN,
			iot_key, ticket->nonce);

	TORMES_LOG(MES_TYPE_DECRYPTEDTICKET);

	//STEP 3: Hand over ticket to initialized circuit.

	circuit_init(&circ_no_1, conn, circ_id);
	circuit_process_fast_ticket(&circ_no_1, ticket);

	return;
}

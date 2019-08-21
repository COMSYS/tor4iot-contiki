#include "tor4iot.h"

#include "circuit.h"
#include "connection.h"
#include "tor_crypto.h"
#include "tor_dtls.h"
#include "tor_delegation.h"
#include "tor_util_format.h"

#include "test_nodes.h"

static struct ctimer timer;
static connection_t conn_no_1;

void *
tor4iot_malloc(size_t size) {
	void* ptr = malloc(size);

	if (ptr == 0) {
		LOG_WARN("Malloc failed!\n");
		while (1)
			;
	}

	return ptr;
}

void tor4iot_free(void* ptr) {
	free(ptr);
}

/*---------------------------------------------------------------------------*/
PROCESS(tor4iot_process, "Tor4IoT");
AUTOSTART_PROCESSES(&tor4iot_process);
/*---------------------------------------------------------------------------*/

static void init_all() {
	TORMES_INIT();

	tor_dtls_init();
}

void handle_connected(connection_t *conn) {
	const char info[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";

	delegation_send_info(conn, (uint8_t *)info, IOT_ID_LEN);
}

uint8_t i = 0;

static void next_mes() {
	TORMES_OUT();

	connect_to_or(&conn_no_1, r1.ip6, r1.port);
}

void handle_circuit_established(circuit_t *circ) {
	connection_t *conn;

	conn = circ->conn;

	circuit_close(circ);

	circ->circ_id++;

	disconnect_from_or(conn);

	ctimer_set(&timer, 3 * CLOCK_SECOND, next_mes, NULL);
}

void handle_response_sent(circuit_t *circ) {
	connection_t *conn;

	conn = circ->conn;

	circuit_close(circ);

	disconnect_from_or(conn);

	ctimer_set(&timer, 3 * CLOCK_SECOND, next_mes, NULL);
}

PROCESS_THREAD( tor4iot_process, ev, data) {
	//static circuit_t circ;
	PROCESS_BEGIN();

#if WATCHDOG_CONF_ENABLE == 1
	LOG_INFO("Watchdog ENABLED\n");
#endif

	init_all();

	PROCESS_YIELD();

	TORMES_SYNC();

	TORMES_LOG(MES_TYPE_START);

	// Connect to Tor entry node
	connect_to_or(&conn_no_1, r1.ip6, r1.port);

	while (1) {
		PROCESS_YIELD();
		if (ev == tcpip_event) {
			tor_dtls_handle_read(&conn_no_1);
		}
	}
	PROCESS_END();
}

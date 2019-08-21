#include "tor4iot.h"

#include "tor_dtls.h"
#include "connection.h"
#include "tor_delegation.h"

#include "contiki-net.h"

static int read_from_peer(struct dtls_context_t *ctx, session_t *session,
		uint8_t *data, size_t len) {
	struct uip_udp_conn *conn = (struct uip_udp_conn *) dtls_get_app_data(ctx);

	LOG_DBG("Got data of length %zd from ", len);
	LOG_DBG_6ADDR(&conn->ripaddr);
	LOG_DBG_(".%u\n", uip_ntohs(conn->rport));

	memcpy(buffer, data, len);

	DUMP_MEMORY("msg", buffer, len);
	conn_handle_input(session->conn, buffer, len);
	return 0;
}

static int send_to_peer(struct dtls_context_t *ctx, session_t *session,
		uint8_t *data, size_t len) {

	struct uip_udp_conn *conn = (struct uip_udp_conn *) dtls_get_app_data(ctx);

	uip_ipaddr_copy(&conn->ripaddr, &session->addr);
	conn->rport = session->port;

	LOG_DBG("\nsend_to_peer\n"
	          "DTLS Context: %p\n"
			  "Session: %p\n"
			  "UDP Connection: %p\n"
			  "IP Address (%p): ", ctx, session, conn, &session->addr);
	LOG_DBG_6ADDR(&session->addr);
	LOG_DBG_("\n");

	LOG_DBG("Sending data of length %zd to ", len);
	LOG_DBG_6ADDR(&conn->ripaddr);
	LOG_DBG_(":%u\n", uip_ntohs(conn->rport));

	uip_udp_packet_send(conn, data, len);

	/* Restore server connection to allow data from any node */
	/* FIXME: do we want this at all? */
	memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
	memset(&conn->rport, 0, sizeof(conn->rport));

	return len;
}

static int handle_event(struct dtls_context_t *ctx, session_t *session,
		dtls_alert_level_t level, unsigned short code) {
	if (level > 0) {
		LOG_WARN("Received DTLS alert message with code %d\n", code);
	} else if (level == 0) {
		switch (code) {
		case DTLS_EVENT_CONNECTED:
			if (!session->conn->already_connected) {
				LOG_DBG("Connected to Tor Relay.\n");
				handle_connected(session->conn);
				session->conn->already_connected = 1;
			}
			break;
		case DTLS_EVENT_CONNECT:
			LOG_DBG("Start to connect to Tor Relay.\n");
			break;
		case DTLS_EVENT_RENEGOTIATE:
			LOG_DBG("Renegotioate with Tor Relay.\n");
			break;
		}
	}

	return 0;
}

#ifdef DTLS_PSK
static unsigned char psk_id[PSK_ID_MAXLEN] = PSK_DEFAULT_IDENTITY;
static size_t psk_id_length = sizeof(PSK_DEFAULT_IDENTITY) - 1;
static unsigned char psk_key[PSK_MAXLEN] = PSK_DEFAULT_KEY;
static size_t psk_key_length = sizeof(PSK_DEFAULT_KEY) - 1;

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__((unused))
#else
#define UNUSED_PARAM
#endif /* __GNUC__ */

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx UNUSED_PARAM,
		const session_t *session UNUSED_PARAM,
		dtls_credentials_type_t type,
		const unsigned char *id, size_t id_len,
		unsigned char *result, size_t result_length)
{

	switch (type)
	{
		case DTLS_PSK_IDENTITY:
		if (result_length < psk_id_length)
		{
			LOG_INFO("cannot set psk_identity -- buffer too small\n");
			return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
		}

		memcpy(result, psk_id, psk_id_length);
		return psk_id_length;
		case DTLS_PSK_KEY:
		if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0)
		{
			LOG_INFO("PSK for unknown id requested, exiting\n");
			return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
		}
		else if (result_length < psk_key_length)
		{
			LOG_INFO("cannot set psk -- buffer too small\n");
			return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
		}

		memcpy(result, psk_key, psk_key_length);
		return psk_key_length;
		default:
		LOG_INFO("unsupported request type: %d\n", type);
	}

	return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}
#endif /* DTLS_PSK */

#ifdef DTLS_ECC
static int
get_ecdsa_key(struct dtls_context_t *ctx,
		const session_t *session,
		const dtls_ecdsa_key_t **result)
{
	static const dtls_ecdsa_key_t ecdsa_key =
	{
		.curve = DTLS_ECDH_CURVE_SECP256R1,
		.priv_key = ecdsa_priv_key,
		.pub_key_x = ecdsa_pub_key_x,
		.pub_key_y = ecdsa_pub_key_y
	};

	*result = &ecdsa_key;
	return 0;
}

static int
verify_ecdsa_key(struct dtls_context_t *ctx,
		const session_t *session,
		const unsigned char *other_pub_x,
		const unsigned char *other_pub_y,
		size_t key_size)
{
	return 0;
}
#endif /* DTLS_ECC */

void tor_dtls_init() {
	dtls_init();
}

uint16_t our_port = 10000;

void tor_dtls_connect(connection_t *conn) {
	dtls_context_t *new_ctx;
	struct uip_udp_conn *new_udp_conn;

	static dtls_handler_t cb = { .write = send_to_peer, .read = read_from_peer,
			.event = handle_event,
#ifdef DTLS_PSK
			.get_psk_info = get_psk_info,
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
			.get_ecdsa_key = get_ecdsa_key,
			.verify_ecdsa_key = verify_ecdsa_key
#endif /* DTLS_ECC */
		};
	LOG_INFO("DTLS client started\n");

	conn->session.conn = conn;

	new_udp_conn = udp_new(&conn->session.addr, 0, NULL);
	if (!new_udp_conn) {
		LOG_WARN("Contiki was not able to open a new UDP socket.\n");
	}

	conn->udp_conn = new_udp_conn;

	udp_bind(conn->udp_conn, uip_htons(our_port));

	our_port++;

	new_ctx = dtls_new_context(conn->udp_conn);
	conn->ctx = new_ctx;

	LOG_DBG("\ntor_dtls_connect\n"
	          "DTLS Context: %p\n"
			  "Session: %p\n"
			  "Tor Connection: %p\n"
			  "UDP Connection: %p\n"
			  "IP Address (%p): ", new_ctx, &conn->session, conn, new_udp_conn, &conn->session.addr);
	LOG_DBG_6ADDR(&conn->session.addr);
	LOG_DBG_("\n");
	
	if (conn->ctx) {
		dtls_set_handler(conn->ctx, &cb);
		LOG_DBG("Set handler\n");
		if (!dtls_connect(conn->ctx, &conn->session)) {
			LOG_INFO("Failed connecting to OR\n");
		}
	}
}

int tor_dtls_disconnect(connection_t *conn) {
	int r;
	r = dtls_close(conn->ctx, &conn->session);
	if (r) {
		LOG_ERR("Failed to close DTLS connection\n");
	}
	dtls_free_context(conn->ctx);
	r &= uip_udp_remove(conn->udp_conn);
	conn->already_connected = 0;
	return r;
}

int tor_dtls_send(connection_t *conn, const uint8_t *buf, size_t buflen) {
	int res;
	DUMP_MEMORY("dtls_msg_out", buf, buflen);
	res = dtls_write(conn->ctx, &conn->session, (uint8_t *) buf, buflen);

	return res;
}

void tor_dtls_handle_read(connection_t *conn) {
	int len;

	if (uip_newdata()) {
		len = uip_datalen();

		((char *) uip_appdata)[uip_datalen()] = 0;

		// DUMP_MEMORY("dtls_ctx", conn->ctx, sizeof(dtls_));
		DUMP_MEMORY("dtls_msg_in", uip_appdata, len);
		dtls_handle_message(conn->ctx, &conn->session, uip_appdata, len);
	}
}

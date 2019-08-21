#ifndef TOR_DELEGATION_H_
#define TOR_DELEGATION_H_

#include "tor4iot.h"
#include "connection.h"

uint8_t circuit_counter;

/**
 * Send the IoT INFO to the IoT Entry used for later ticket assignment.
 */
void
delegation_send_info(connection_t *conn, uint8_t *info, size_t infolen);

/**
 * Process incoming tickets.
 */
void
delegation_process_ticket(connection_t *conn, iot_ticket_t *ticket);

void
delegation_process_fast_ticket(connection_t *conn, iot_fast_ticket_t *ticket, uint32_t circ_id);

#endif /* TOR_DELEGATION_H_ */

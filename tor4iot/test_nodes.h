#ifndef TEST_NODES_H_
#define TEST_NODES_H_

#include "circuit.h"

static const uint8_t r1_ip4[] = {127, 0, 0, 1};
static const uint16_t r1_ip6[] = {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};
#define r1_port 5000

struct tor_node_raw r1 = {
        .ip4 = r1_ip4,
	.ip6 = r1_ip6,
	.port = r1_port,
};

#endif /* TEST_NODES_H_ */

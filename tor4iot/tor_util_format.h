/* This file contains code taken from the Tor Project ! */

#ifndef TOR_UTIL_FORMAT_H_
#define TOR_UTIL_FORMAT_H_

#include "tor4iot.h"

int
hex_digest_nickname_decode(const char *hexdigest, char *digest_out);

int
base64_decode(char *dest, size_t destlen, const char *src, size_t srclen);

#endif /* TOR_UTIL_FORMAT_H_ */

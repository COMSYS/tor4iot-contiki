CONTIKI_PROJECT = tor4iot
all: $(CONTIKI_PROJECT)

PROJECT_SOURCEFILES += circuit.c              \
                       connection.c           \
                       tor_crypto.c           \
                       tor_dtls.c             \
                       keccak-tiny-unrolled.c \
                       tor_util_format.c      \
                       tor_delegation.c       \
                       sha1.c

PROJECTDIRS += libs/sha1 libs/keccak-tiny

MODULES += os/net/app-layer/tor

CONTIKI=..
include $(CONTIKI)/Makefile.include

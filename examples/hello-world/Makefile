CONTIKI_PROJECT = hello-world
all: $(CONTIKI_PROJECT)

CFLAGS+= -ffunction-sections
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__

CONTIKI = ../..
include $(CONTIKI)/Makefile.include

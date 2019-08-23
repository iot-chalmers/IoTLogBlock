CONTIKI_PROJECT = chain-originator chain-responder
all: $(CONTIKI_PROJECT)
TARGET=openmote-cc2538
# MAC_ROUTING=ROUTING_CONF_NULLROUTING
# MAKE_MAC = MAKE_MAC_OTHER
MAKE_NET = MAKE_NET_IPV6
# MAKE_ROUTING = MAKE_ROUTING_NULLROUTING

#DEBUGFLAGS  = -O0 -D _DEBUG
#CFLAGS += -ggdb
#CFLAGS += -O0
#CFLAGS_OPT ?= -Os
#CFLAGS_DEBUG ?= -ggdb3 -fomit-frame-pointer
#CFLAGS  += -Os        # O2 for size
#CFLAGS  += -O0        # do not optimize
#CFLAGS  += -Og   #debugging friendly
#CFLAGS  += -fverbose-asm
#CFLAGS  += -ggdb    #info for the debugger
#CFLAGS += -O0 -mcpu=cortex-m3 -mthumb -mlittle-endian
#CFLAGS += -fshort-enums -fomit-frame-pointer -fno-strict-aliasing
#CFLAGS += -Wall
#CFLAGS += -gdwarf-2
#LDFLAGS += -mcpu=cortex-m3 -mthumb -nostartfiles
#LDFLAGS += -T $(LDSCRIPT)
#LDFLAGS += -Wl,-Map=$(@:.elf=-$(TARGET).map),--cref,--no-warn-mismatch
#OBJCOPY_FLAGS += -O binary --gap-fill 0xff

.PHONY: renode
renode: all
ifneq ($(TARGET),cc2538dk)
	$(error Only the cc2538dk TARGET is supported for Renode demo scripts)
endif
ifndef SCRIPT
	$(warning SCRIPT not defined! Using "rpl-udp.resc" as default)
	renode rpl-udp.resc
else
ifeq ($(wildcard $(SCRIPT)),)
	$(error SCRIPT "$(SCRIPT)" does not exist!)
endif
	renode $(SCRIPT)
endif

CONTIKI=../
include $(CONTIKI)/Makefile.include

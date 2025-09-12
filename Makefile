CC       ?= cc
CFLAGS   ?= -O2
CFLAGS   += -Wall -Wextra -Wpedantic -std=c11
# If you want even stricter checks, uncomment:
# CFLAGS   += -Wshadow -Wconversion -Wmissing-prototypes -Wstrict-prototypes

RM       ?= rm -f

OPENSSL_PKG := $(shell pkg-config --exists openssl    && echo openssl    || \
                        pkg-config --exists openssl@3 && echo openssl@3 || echo)

ifeq ($(strip $(OPENSSL_PKG)),)
  OPENSSL_CFLAGS :=
  OPENSSL_LIBS   :=
else
  OPENSSL_CFLAGS := $(shell pkg-config --cflags $(OPENSSL_PKG) 2>/dev/null)
  OPENSSL_LIBS   := $(shell pkg-config --libs   $(OPENSSL_PKG) 2>/dev/null)
endif

ifeq ($(strip $(OPENSSL_LIBS)),)
  LDLIBS   += -lcrypto
else
  CPPFLAGS += $(OPENSSL_CFLAGS)
  LDLIBS   += $(OPENSSL_LIBS)
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  CPPFLAGS += -DMAC_OSX

  ifeq ($(strip $(OPENSSL_LIBS)),)
    HB_ARM   := /opt/homebrew/opt/openssl@3
    HB_INTEL := /usr/local/opt/openssl@3
    ifneq ("$(wildcard $(HB_ARM)/include/openssl)","")
      CPPFLAGS += -I$(HB_ARM)/include
      LDFLAGS  += -L$(HB_ARM)/lib
    endif
    ifneq ("$(wildcard $(HB_INTEL)/include/openssl)","")
      CPPFLAGS += -I$(HB_INTEL)/include
      LDFLAGS  += -L$(HB_INTEL)/lib
    endif
    ifneq ("$(wildcard /opt/local/include/openssl)","")
      CPPFLAGS += -I/opt/local/include
      LDFLAGS  += -L/opt/local/lib
    endif
  endif
endif

.PHONY: all clean debug
all: vfdecrypt

vfdecrypt: vfdecrypt.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

vfdecrypt.o: vfdecrypt.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

debug: CFLAGS := -O0 -g -Wall -Wextra -Wpedantic -std=c11
debug: clean vfdecrypt

clean:
	$(RM) vfdecrypt vfdecrypt.o *~

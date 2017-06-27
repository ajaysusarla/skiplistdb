#twoskip

CCCOLOUR="\033[34m"
LINKCOLOUR="\033[34;1m"
SRCCOLOUR="\033[33m"
BINCOLOUR="\033[37;1m"
MAKECOLOUR="\033[32;1m"
RMCOLOUR="\033[31m"
ENDCOLOUR="\033[0m"

## Silent by default
V =
ifeq ($(strip $(V)),)
	E = @echo
	Q = @
	QCC = @printf '    %b %b\n' $(CCCOLOUR)CC$(ENDCOLOUR) $(SRCCOLOUR)$@$(ENDCOLOUR) 1>&2;
	QLD = @printf '    %b %b\n' $(LINKCOLOUR)LINK$(ENDCOLOUR) $(BINCOLOUR)$@$(ENDCOLOUR) 1>&2;
	QIN = @printf '    %b %b\n' $(LINKCOLOUR)INSTALL$(ENDCOLOUR) $(BINCOLOUR)$@$(ENDCOLOUR) 1>&2;
	QRM = @printf '    %b %b\n' $(RMCOLOUR)RM$(ENDCOLOUR) $(BINCOLOUR)$@$(ENDCOLOUR) 1>&2;
else
	E = @\#
	Q =
endif
export E Q QCC QLD QIN

NULL=
PREFIX?=/usr/local
INSTALL_BIN=$(PREFIX)/bin
INSTALL=install
CC=gcc

TS_CFLAGS=-std=c99 -pedantic -Wall -W -Wno-missing-field-initializers -O0 $(CFLAGS) $(DEBUG)
TS_LDFLAGS=$(LDFLAGS) $(DEBUG)
TS_LIBS=
DEBUG=-g -ggdb

TS_CC=$(QCC)$(CC) $(TS_CFLAGS)
TS_LD=$(QLD)$(CC) $(TS_LDFLAGS)
TS_INSTALL=$(QIN)$(INSTALL)
TS_RM=$(QRM)rm -rf

# Object files
TS_OBJS =           \
	cstring.o   \
	twoskip.o   \
	util.o      \
	ts-test.o   \
	$(NULL)

# Headers
TS_HDRS =           \
	cstring.h   \
	twoskip.h   \
	util.h 	    \
	$(NULL)

TWOSKIP_TEST=ts-test

all: $(TWOSKIP_TEST)

Makefile.dep:
	$(TS_CC) -MM *.c > Makefile.dep 2> /dev/null || true

-include Makefile.dep

%.o:  %.c
	$(TS_CC) -c $<

$(TWOSKIP_TEST): $(TS_OBJS) $(TS_HDRS)
	$(TS_LD) -o $@ $^ $(TS_LIBS)

clean:
	$(TS_RM) $(TS_OBJS) $(TWOSKIP_TEST) *.o Makefile.dep

.PHONY: all clean

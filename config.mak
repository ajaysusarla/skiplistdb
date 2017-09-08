## Silent by default

CCCOLOUR="\033[34m"
LINKCOLOUR="\033[34;1m"
SRCCOLOUR="\033[33m"
BINCOLOUR="\033[37;1m"
MAKECOLOUR="\033[32;1m"
RMCOLOUR="\033[31m"
ARCOLOUR="\033[35m"
ENDCOLOUR="\033[0m"

V =
ifeq ($(strip $(V)),)
	E = @echo
	Q = @
	QCC = @printf '    %b %b\n' $(CCCOLOUR)CC$(ENDCOLOUR) $(SRCCOLOUR)$@$(ENDCOLOUR) 1>&2;
	QLD = @printf '    %b %b\n' $(LINKCOLOUR)LINK$(ENDCOLOUR) $(BINCOLOUR)$@$(ENDCOLOUR) 1>&2;
	QIN = @printf '    %b %b\n' $(LINKCOLOUR)INSTALL$(ENDCOLOUR) $(BINCOLOUR)$@$(ENDCOLOUR) 1>&2;
	QRM = @printf '    %b %b\n' $(RMCOLOUR)RM$(ENDCOLOUR) $(BINCOLOUR)$@$(ENDCOLOUR) 1>&2;
	QAR = @printf '    %b %b\n' $(ARCOLOUR)AR$(ENDCOLOUR) $(BINCOLOUR)$@$(ENDCOLOUR) 1>&2;
	QMKDIR = @printf '    %b %b\n' $(RMCOLOUR)MKDIR$(ENDCOLOUR) $(BINCOLOUR)$@$(ENDCOLOUR) 1>&2;
else
	E = @\#
	Q =
endif
export E Q QCC QLD QIN QMKDIR QAR

## Defaults
NULL=
PREFIX?=/usr/local
INSTALL_BIN=$(PREFIX)/bin
INSTALL=install
CC=gcc
AR_LIB_FILE=libskiplistdb.a
SO_LIB_FILE=

## Aliases
SDB_INSTALL=$(QIN)$(INSTALL)
SDB_RM=$(QRM)rm -rf
SDB_MKDIR=$(QMKDIR)mkdir -p
SDB_AR=$(QAR)ar

# Compiler options
SDB_CFLAGS=-std=c99 -pedantic -Wall -W -Wno-missing-field-initializers -O0 $(CFLAGS) $(DEBUG)
SDB_LDFLAGS=$(LDFLAGS) $(DEBUG)
SDB_LIBS=
DEBUG=-g -ggdb
ARFLAGS=rcs

SDB_CC=$(QCC)$(CC) $(SDB_CFLAGS)
SDB_LD=$(QLD)$(CC) $(SDB_LDFLAGS)

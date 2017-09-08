#twoskip
-include ../config.mak

TS_CFLAGS=-std=c99 -pedantic -Wall -W -Wno-missing-field-initializers -O0 $(CFLAGS) $(DEBUG)
TS_LDFLAGS=$(LDFLAGS) $(DEBUG)
TS_LIBS=
DEBUG=-g -ggdb

TS_CC=$(QCC)$(CC) $(TS_CFLAGS)
TS_LD=$(QLD)$(CC) $(TS_LDFLAGS)

# Object files
TS_OBJS =           \
	cstring.o   \
	twoskip.o   \
	util.o      \
	mappedfile.o \
	ts-example.o   \
	$(NULL)

# Headers
TS_HDRS =           \
	cstring.h   \
	twoskip.h   \
	util.h 	    \
	macros.h    \
	mappedfile.h \
	$(NULL)

TWOSKIP_EXAMPLE=ts-example

all: $(TWOSKIP_EXAMPLE)

Makefile.dep:
	$(TS_CC) -MM *.c > Makefile.dep 2> /dev/null || true

-include Makefile.dep

%.o:  %.c
	$(TS_CC) -c $<

$(TWOSKIP_EXAMPLE): $(TS_OBJS)
	$(TS_LD) -o $@ $^ $(TS_LIBS)

clean:
	$(TS_RM) $(TS_OBJS) $(TWOSKIP_EXAMPLE) *.o Makefile.dep

check-syntax:
	$(CC) $(CFLAGS) -Wextra -pedantic -fsyntax-only $(CHK_SOURCES)

.PHONY: all clean check-syntax

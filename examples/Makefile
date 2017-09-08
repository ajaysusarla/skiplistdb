#examples
-include ../config.mak

# Object files
TS_OBJS =           	\
	ts-example.o   	\
	$(NULL)

ZS_OBJS =           	\
	zs-example.o	\
	$(NULL)

# Headers
TS_HDRS =           	\
	$(NULL)

ZS_HDRS =           	\
	$(NULL)


TWOSKIP_EXAMPLE=ts-example
ZEROSKIP_EXAMPLE=zs-example

SKIPLISTDB_INC=../src

all: $(TWOSKIP_EXAMPLE) $(ZEROSKIP_EXAMPLE)

Makefile.dep:
	$(TS_CC) -MM *.c > Makefile.dep 2> /dev/null || true

-include Makefile.dep

%.o:  %.c
	$(TS_CC) -I$(SKIPLISTDB_INC) -c $<

$(TWOSKIP_EXAMPLE): $(TS_OBJS)
	$(TS_LD) -I$(SKIPLISTDB_INC) -o $@ $^ ../src/$(AR_LIB_FILE)

$(ZEROSKIP_EXAMPLE): $(ZS_OBJS)
	$(TS_LD) -I$(SKIPLISTDB_INC) -o $@ $^ ../src/$(AR_LIB_FILE)

clean:
	$(TS_RM) $(TS_OBJS) $(ZS_OBJS) $(TWOSKIP_EXAMPLE) $(ZEROSKIP_EXAMPLE) \
	*.o Makefile.dep

check-syntax:
	$(CC) $(CFLAGS) -Wextra -pedantic -fsyntax-only $(CHK_SOURCES)

.PHONY: all clean check-syntax

#examples
-include ../config.mk

# Object files
TS_OBJS =           	\
	ts-example.o   	\
	$(NULL)

ZS_OBJS =           	\
	zs-example.o	\
	$(NULL)

BT_OBJS =           	\
	bt-example.o	\
	$(NULL)

MF_OBJS =           	\
	mf-example.o	\
	$(NULL)

STRARRAY_OBJS =           	\
	strarray-example.o	\
	$(NULL)

CONFIG_OBJS =           	\
	config-example.o	\
	$(NULL)

FLOCK_OBJS =           	\
	flock-example.o	\
	$(NULL)

# Headers
TS_HDRS =           	\
	$(NULL)

ZS_HDRS =           	\
	$(NULL)


TWOSKIP_EXAMPLE=ts-example
ZEROSKIP_EXAMPLE=zs-example
BT_EXAMPLE=bt-example
MF_EXAMPLE=mf-example
STRARRAY_EXAMPLE=strarray-example
CONFIG_EXAMPLE=config-example
FLOCK_EXAMPLE=flock-example

SKIPLISTDB_INC=../src
ZS_LIBS+=
TS_LIBS+=
MF_LIBS+=
STRARRAY_LIBS+=

all: $(TWOSKIP_EXAMPLE) $(ZEROSKIP_EXAMPLE) $(BT_EXAMPLE) $(MF_EXAMPLE) $(STRARRAY_EXAMPLE) $(CONFIG_EXAMPLE) $(FLOCK_EXAMPLE)

Makefile.dep:
	$(SDB_CC) -MM *.c > Makefile.dep 2> /dev/null || true

-include Makefile.dep

%.o:  %.c
	$(SDB_CC) -I$(SKIPLISTDB_INC) -c $<

$(TWOSKIP_EXAMPLE): $(TS_OBJS)
	$(SDB_LD) -I$(SKIPLISTDB_INC) -o $@ $^ ../src/$(AR_LIB_FILE) $(TS_LIBS)

$(ZEROSKIP_EXAMPLE): $(ZS_OBJS)
	$(SDB_LD) -I$(SKIPLISTDB_INC) -o $@ $^ ../src/$(AR_LIB_FILE) $(ZS_LIBS)

$(BT_EXAMPLE): $(BT_OBJS)
	$(SDB_LD) -I$(SKIPLISTDB_INC) -o $@ $^ ../src/$(AR_LIB_FILE) $(BT_LIBS)

$(MF_EXAMPLE): $(MF_OBJS)
	$(SDB_LD) -I$(SKIPLISTDB_INC) -o $@ $^ ../src/$(AR_LIB_FILE) $(MF_LIBS)

$(STRARRAY_EXAMPLE): $(STRARRAY_OBJS)
	$(SDB_LD) -I$(SKIPLISTDB_INC) -o $@ $^ ../src/$(AR_LIB_FILE) $(STRARRAY_LIBS)

$(CONFIG_EXAMPLE): $(CONFIG_OBJS)
	$(SDB_LD) -I$(SKIPLISTDB_INC) -o $@ $^ ../src/$(AR_LIB_FILE)

$(FLOCK_EXAMPLE): $(FLOCK_OBJS)
	$(SDB_LD) -I$(SKIPLISTDB_INC) -o $@ $^ ../src/$(AR_LIB_FILE)

clean:
	$(SDB_RM) $(TS_OBJS) $(ZS_OBJS) $(TWOSKIP_EXAMPLE) $(ZEROSKIP_EXAMPLE) \
	$(BT_OBJS) $(BT_EXAMPLE) $(STRARRAY_OBJS) $(STRARRAY_EXAMPLE) \
	$(CONFIG_EXAMPLE) $(FLOCK_EXAMPLE) *.o Makefile.dep

check-syntax:
	$(CC) $(CFLAGS) -Wextra -pedantic -fsyntax-only $(CHK_SOURCES)

.PHONY: all clean check-syntax

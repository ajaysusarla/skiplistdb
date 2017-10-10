# Tool for skiplistdb
-include ../config.mk

TOOL_OBJS =			\
	cmd.o			\
	cmd-backends.o 		\
	cmd-batch.o		\
	cmd-consistent.o	\
	cmd-damage.o		\
	cmd-delete.o		\
	cmd-dump.o		\
	cmd-get.o		\
	cmd-repack.o		\
	cmd-set.o		\
	cmd-show.o		\
	skiplistdb.o 		\
	$(NULL)

TOOL_HDRS = 	\
	cmds.h 	\
	$(NULL)

DBTOOL=skiplistdb

SKIPLISTDB_INC=../src

all: $(DBTOOL)

Makefile.dep:
	$(SDB_CC) -MM *.c > Makefile.dep 2> /dev/null || true

-include Makefile.dep

%.o: %.c
	$(SDB_CC) -I$(SKIPLISTDB_INC) -c $<

$(DBTOOL): $(TOOL_OBJS)
	$(SDB_LD) -I$(SKIPLISTDB_INC) -o $@ $^ ../src/$(AR_LIB_FILE)

clean:
	$(SDB_RM) $(TOOL_OBJS) $(DBTOOL) *.o Makefile.dep

check-syntax:
	$(CC) $(CFLAGS) -Wextra -pedantic -fsyntax-only $(CHK_SOURCES)

.PHONY: all clean check-syntax


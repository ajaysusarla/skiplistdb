#skiplistbd library
-include ../config.mk

# Object files
SDB_LIBOBJS =          	\
	cstring.o   	\
	twoskip.o   	\
	util.o      	\
	mappedfile.o 	\
	htable.o	\
	skiplistdb.o	\
	$(NULL)

# Headers
SDB_HDRS =           	\
	cstring.h   	\
	twoskip.h   	\
	util.h 	    	\
	macros.h    	\
	mappedfile.h 	\
	htable.h	\
	skiplistdb.h	\
	$(NULL)

all: clean-ar $(AR_LIB_FILE)

Makefile.dep:
	$(SDB_CC) -MM *.c > Makefile.dep 2> /dev/null || true

-include Makefile.dep

%.o:  %.c
	$(SDB_CC) -c $<

$(AR_LIB_FILE): $(SDB_LIBOBJS)
	$(SDB_AR) $(ARFLAGS) $@ $^

clean-ar:
	$(SDB_RM) $(AR_LIB_FILE)

clean:
	$(SDB_RM) $(SDB_LIBOBJS) $(AR_LIB_FILE) *.o Makefile.dep

check-syntax:
	$(CC) $(CFLAGS) -Wextra -pedantic -fsyntax-only $(CHK_SOURCES)

.PHONY: all clean check-syntax clean-ar

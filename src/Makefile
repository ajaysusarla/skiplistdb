#skiplistbd library
-include ../config.mak

# Object files
SDB_LIBOBJS =           	\
	cstring.o   	\
	twoskip.o   	\
	util.o      	\
	mappedfile.o 	\
	$(NULL)

# Headers
SDB_HDRS =           	\
	cstring.h   	\
	twoskip.h   	\
	util.h 	    	\
	macros.h    	\
	mappedfile.h 	\
	$(NULL)

all: $(AR_LIB_FILE)

Makefile.dep:
	$(SDB_CC) -MM *.c > Makefile.dep 2> /dev/null || true

-include Makefile.dep

%.o:  %.c
	$(SDB_CC) -c $<

$(AR_LIB_FILE): $(SDB_LIBOBJS)
	$(SDB_RM) $@ && $(SDB_AR) $(ARFLAGS) $@ $^

clean:
	$(SDB_RM) $(SDB_LIBOBJS) $(AR_LIB_FILE) *.o Makefile.dep

check-syntax:
	$(CC) $(CFLAGS) -Wextra -pedantic -fsyntax-only $(CHK_SOURCES)

.PHONY: all clean check-syntax

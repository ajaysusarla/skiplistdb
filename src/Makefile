#skiplistbd library
-include ../config.mak

# Object files
TS_LIBOBJS =           	\
	cstring.o   	\
	twoskip.o   	\
	util.o      	\
	mappedfile.o 	\
	$(NULL)

# Headers
TS_HDRS =           	\
	cstring.h   	\
	twoskip.h   	\
	util.h 	    	\
	macros.h    	\
	mappedfile.h 	\
	$(NULL)

TWOSKIP_EXAMPLE=ts-example

all: $(AR_LIB_FILE)

Makefile.dep:
	$(TS_CC) -MM *.c > Makefile.dep 2> /dev/null || true

-include Makefile.dep

%.o:  %.c
	$(TS_CC) -c $<

$(AR_LIB_FILE): $(TS_LIBOBJS)
	$(TS_RM) $@ && $(TS_AR) $(ARFLAGS) $@ $^

clean:
	$(TS_RM) $(TS_LIBOBJS) $(AR_LIB_FILE) *.o Makefile.dep

check-syntax:
	$(CC) $(CFLAGS) -Wextra -pedantic -fsyntax-only $(CHK_SOURCES)

.PHONY: all clean check-syntax

PROG=psampletest
HEADERS=

# compiler
#CC= g++
CC= gcc -std=gnu99
#LD=ld
LD=gcc

# optimization
OPT_ALL= -O3 -DNDEBUG
OPT_REG= -g -O2
OPT_DBG= -g -ggdb
ifndef OPT
  OPT=$(OPT_REG)
endif

# CFLAGS and LIBS
CFLAGS = $(OPT) -D_GNU_SOURCE
CFLAGS += -Wall -Wstrict-prototypes -Wunused-value
CFLAGS += -Wunused-function
LIBS=

OBJS= $(PROG).o

all: $(OBJS) $(PROG)

psampletest: $(OBJS) $(HEADERS) Makefile
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

#########  install  #########

install: all
	install -m 700 $(PROG) /usr/sbin

#########  clean   #########

clean: 
	rm -f $(PROG) $(OBJS)

#########  dependencies  #########

.c.o: $(HEADERS) Makefile
	$(CC) $(CFLAGS) -c $*.c

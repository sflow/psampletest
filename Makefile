PROG=psampletest dropmontest diagtest ethtooltest
OBJS= psampletest.o dropmontest.o diagtest.o ethtooltest.o
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
  OPT=$(OPT_DBG)
endif

# CFLAGS and LIBS
CFLAGS = $(OPT) -D_GNU_SOURCE
CFLAGS += -Wall -Wstrict-prototypes
CFLAGS += -Wno-unused-but-set-variable
CFLAGS += -Wno-unused-function
LIBS=


all: $(PROG)

psampletest: psampletest.o $(HEADERS) Makefile
	$(CC) $(CFLAGS) -o $@ psampletest.o $(LIBS)

dropmontest: dropmontest.o $(HEADERS) Makefile
	$(CC) $(CFLAGS) -o $@ dropmontest.o $(LIBS)

diagtest: diagtest.o $(HEADERS) Makefile
	$(CC) $(CFLAGS) -o $@ diagtest.o $(LIBS)

ethtooltest: ethtooltest.o $(HEADERS) Makefile
	$(CC) $(CFLAGS) -o $@ ethtooltest.o $(LIBS)

usersocktest: usersocktest.o $(HEADERS) Makefile
	$(CC) $(CFLAGS) -o $@ usersocktest.o $(LIBS)

usersocktest_reader: usersocktest_reader.o Makefile
	$(CC) $(CFLAGS) -o $@ usersocktest_reader.o $(LIBS)

usersocktest_sender: usersocktest_sender.o Makefile
	$(CC) $(CFLAGS) -o $@ usersocktest_sender.o $(LIBS)

#########  install  #########

install: all
	install -m 700 $(PROG) /usr/sbin

#########  clean   #########

clean: 
	rm -f $(PROG) $(OBJS)

#########  dependencies  #########

.c.o:
	$(CC) $(CFLAGS) -c $*.c

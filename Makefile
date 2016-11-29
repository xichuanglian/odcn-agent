# Default target.
all:

ifndef PROJECT_INCLUDE
PROJECT_INCLUDE = ./include
endif

CC = gcc

OPT = -Os
CFLAGS = -I$(PROJECT_INCLUDE) -I/usr/include/libnl3 -std=gnu11 -Wall -Wno-unused-result -Werror -g $(OPT)
LDFLAGS = -lnl-3 -lnl-genl-3

./bin/nl_client.o: nl_client.c
	$(CC) $(CFLAGS) -c -o $@ $<

./bin/agent.o: agent.c
	$(CC) $(CFLAGS) -c -o $@ $<

./bin/agent: ./bin/agent.o ./bin/nl_client.o
	$(CC) -o $@ $^ $(LDFLAGS)

all: ./bin/agent

clean:
	rm -f ./bin/*.o ./bin/agent


.PHONY: all clean

CC = gcc
CFLAGS = -fno-stack-protector -no-pie

all: chain_reactor

chain_reactor: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f chain_reactor

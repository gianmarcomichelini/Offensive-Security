CC = gcc
CFLAGS = -fno-stack-protector -no-pie -g

all: recycler

recycler: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f recycler

CC = gcc
CFLAGS = -fno-stack-protector -no-pie

all: forge

forge: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f forge

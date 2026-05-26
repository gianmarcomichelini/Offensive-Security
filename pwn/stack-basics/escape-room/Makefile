CC = gcc
CFLAGS = -fno-stack-protector -no-pie -O0 -g

all: escape_room

escape_room: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f escape_room

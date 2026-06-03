CC = gcc
CFLAGS = -fno-stack-protector -no-pie -g

all: inventory_slot

inventory_slot: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f inventory_slot

CC = gcc
CFLAGS = -fno-stack-protector -no-pie -O0 -g

all: guestbook

guestbook: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f guestbook

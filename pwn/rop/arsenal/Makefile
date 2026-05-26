CC = gcc
CFLAGS = -fno-stack-protector -no-pie -static

all: arsenal

arsenal: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f arsenal

CC = gcc
CFLAGS = -fno-stack-protector -no-pie

all: toolkit

toolkit: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f toolkit

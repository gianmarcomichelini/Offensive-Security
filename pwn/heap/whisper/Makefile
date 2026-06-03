CC = gcc
CFLAGS = -fno-stack-protector -no-pie -g

all: whisper

whisper: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f whisper

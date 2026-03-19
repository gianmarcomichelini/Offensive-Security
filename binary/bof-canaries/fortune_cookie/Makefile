CC = gcc
CFLAGS = -fstack-protector-all -no-pie

all: fortune_cookie

fortune_cookie: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f fortune_cookie

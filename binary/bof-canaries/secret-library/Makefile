CC = gcc
CFLAGS = -no-pie -fstack-protector-all -Wno-format-security

all: secret_library

secret_library: main.c
	$(CC) $(CFLAGS) -o secret_library main.c

clean:
	rm -f secret_library

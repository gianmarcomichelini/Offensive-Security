CC = gcc
CFLAGS = -fno-stack-protector -no-pie -fno-builtin-printf

all: ret2libc_home

ret2libc_home: main.c
	$(CC) $(CFLAGS) -o ret2libc_home main.c

clean:
	rm -f ret2libc_home

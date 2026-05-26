CC = gcc
CFLAGS = -fno-stack-protector -no-pie

all: ret2libc_aslr

ret2libc_aslr: main.c
	$(CC) $(CFLAGS) -o ret2libc_aslr main.c

clean:
	rm -f ret2libc_aslr

CC = gcc
# Partial RELRO with lazy binding so .got.plt is writable at runtime.
# -fno-builtin-printf prevents gcc from folding printf("...\n") into
# puts("..."), which would silently leak puts@plt into the binary.
CFLAGS = -fno-stack-protector -no-pie -fno-builtin-printf \
         -Wl,-z,relro -Wl,-z,lazy

all: padlock

padlock: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f padlock

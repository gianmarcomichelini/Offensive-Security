CC = gcc
CFLAGS = -fno-stack-protector -no-pie -g

all: account_vault

account_vault: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f account_vault

CC = gcc
CFLAGS = -fno-stack-protector -z execstack -no-pie -O0 -g

all: whispered_secrets

whispered_secrets: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f whispered_secrets

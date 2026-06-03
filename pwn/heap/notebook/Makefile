CC = gcc
CFLAGS = -fno-stack-protector -no-pie -g

all: notebook

notebook: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f notebook

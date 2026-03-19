CC = gcc
CFLAGS = -fstack-protector-all -no-pie

all: cafe_menu

cafe_menu: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f cafe_menu

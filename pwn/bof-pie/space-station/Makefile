CC = gcc
CFLAGS = -fPIE -pie -fstack-protector-all -Wno-format-security

all: space_station

space_station: main.c
	$(CC) $(CFLAGS) -o space_station main.c

clean:
	rm -f space_station

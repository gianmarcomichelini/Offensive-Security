CC = gcc
CFLAGS = -fstack-protector-all -no-pie

all: weather_station

weather_station: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f weather_station

CC=gcc
CFLAGS=-Wall -g

simulator: simulator.c
	$(CC) $(CFLAGS) -o simulator simulator.c -lm

clean:
	rm simulator

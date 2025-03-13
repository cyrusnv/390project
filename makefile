# Makefile
CC = gcc
CFLAGS = -g -Wall

all: target tracer

target: target.c
	$(CC) $(CFLAGS) -o target target.c

tracer: tracer.c
	$(CC) $(CFLAGS) -o tracer tracer.c

clean:
	rm -f target tracer
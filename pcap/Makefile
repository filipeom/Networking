CC=gcc
CFLAGS=-Wall
file=tcpsniffer

all:
	$(CC) $(CFLAGS) $(file).c ../networking.c -lpcap -o $(file)

clean:
	rm $(file) 

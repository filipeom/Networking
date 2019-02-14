CC=gcc
CFLAGS= -lpcap -lnet
TARGET=arpspoof

all:
	$(CC) $(TARGET).c -o $(TARGET) $(CFLAGS)

ping:
	$(CC) ping.c -o ping $(CFLAGS)

clean:
	rm $(TARGET) ping

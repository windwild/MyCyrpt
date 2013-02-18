CC=g++
CFLAGS=-Wall -g -O2
LIBS=-lcrypto

all: mycrypt

mycrypt: mycrypt.c
	$(CC) $(CFLAGS) mycrypt.c -o $@ $(LIBS)

clean:
	@rm -f mycrypt

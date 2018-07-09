CC=cc

server: server.o protocol.c
	$(CC) -o server.x server.o -lwebsockets -lssl -lcrypto

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: server

clean:
	rm *.o server.x

CC=cc

client: client.o protocol.c
	$(CC) -o client.x client.o -lwebsockets

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: client

clean:
	rm *.o client.x

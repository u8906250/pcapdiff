CFLAGS = -O2 -Wall

all: pcapdiff

pcapdiff: main.c
	$(CC) $(CFLAGS) -o pcapdiff $^ $(LDFLAGS)

clean:
	rm -f pcapdiff *~

CC=gcc -g -Wall
CFLAGS=
LFLAGS= -lpcap

all: pcapreader

pcapreader: src/main.c 
	$(CC) -o $@ src/main.c $(LFLAGS)

.c.o:
	$(CC) -c $? -o $@ $(LFLAGS) $(LC_FLAGS)

# clean all the .o and executable files
clean:
	rm -rf *.o pcapreader


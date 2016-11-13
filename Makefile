CC = 
DEBUG = -g
LIBRARY = -lssl -lm -lcrypto
FILE = exchang.c

ifeq ($(shell uname -s), Linux)
CC = gcc
else ifeq ($(shell uname -s), FreeBSD)
CC = clang
endif

all:
	$(CC) $(DEBUG) $(FILE) $(LIBRARY)

clean:
	rm -f *.out
	rm -f *.core

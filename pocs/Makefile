
POCS := $(patsubst %.c, %.exe, $(wildcard *.c))

all: $(POCS)

%.exe: %.c
	gcc -s -O2 -Wall -std=c99 -o $@ $^

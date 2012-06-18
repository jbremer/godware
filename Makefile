
%.exe: %.c
	gcc -std=c99 -s -O2 -Wall -o $@ $^

default: poc2.exe
	../../../ia32/bin/pin -t obj-ia32/godware.dll -- poc2.exe msgbox.exe

tar: poc2.c Nmakefile godware.cpp rebuild.py obj-ia32/godware.dll poc2.exe \
		msgbox.exe Makefile
	tar cf runpe-pin.tar $^

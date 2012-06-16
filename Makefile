
%.exe: %.c
	gcc -std=c99 -s -O2 -Wall -o $@ $^

default: poc2.exe
	../../../ia32/bin/pin -t obj-ia32/godware.dll -- poc2.exe D:\msgbox.exe

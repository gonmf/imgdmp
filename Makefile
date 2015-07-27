all:
	gcc server.c -std=c99 -Wall -O2 -o server.elf -lz
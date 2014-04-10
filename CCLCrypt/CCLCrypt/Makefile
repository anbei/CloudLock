#
# Makefile for aescrypt
# Copyright (C) 2007, 2008, 2009, 2013
# Paul E. Jones <paulej@packetizer.com>
#
# This software is licensed as "freeware."  Permission to distribute
# this software in source and binary forms is hereby granted without a
# fee.  THIS SOFTWARE IS PROVIDED 'AS IS' AND WITHOUT ANY EXPRESSED OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
# THE AUTHOR SHALL NOT BE HELD LIABLE FOR ANY DAMAGES RESULTING FROM THE
# USE OF THIS SOFTWARE, EITHER DIRECTLY OR INDIRECTLY, INCLUDING, BUT
# NOT LIMITED TO, LOSS OF DATA OR DATA BEING RENDERED INACCURATE.
#

#changed by Sunzhimin <zhimins@gmail.com> 2014.04.10
CC=g++

#The below line is for debugging
#CFLAGS=-I. -ggdb -Wall -D_FILE_OFFSET_BITS=64
CFLAGS=-Wall -D_FILE_OFFSET_BITS=64

LIBS=


all: aescryptlib demo

LIBO = aescrypt.o aes.o sha256.o  CCLCrypt.o base64.o

aescryptlib: $(LIBO)
	ar rcs libcryptfile.a $(LIBO)

demo : $(LIBO) linuxdemo.o
	$(CC) $(CFLAGS) linuxdemo.o -L. -lcryptfile -o demo 


clean:
	rm -f *.o *.a demo
	
.SUFFIXES: .cpp .o
.cpp.o:
	$(CC) $(CFLAGS) -c $*.cpp
.SUFFIXES: .c .o
.c.o:
	gcc $(CFLAGS) -c $*.c

#!/bin/sh

WREmu: *.c *.h
	gcc *.c -lpcap -o WREmu

clean: 
	rm WREmu *~
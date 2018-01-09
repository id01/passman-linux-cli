#!/bin/sh

g++ -c ../main/linux.cpp -O2 -lcrypto -lssl -lcurl -lcryptopp -o ../main/linux.o
g++ cli.cpp ../scrypt-jane/scrypt-jane.o ../main/linux.o -O2 -lcrypto -lssl -lcurl -lcryptopp -o cli
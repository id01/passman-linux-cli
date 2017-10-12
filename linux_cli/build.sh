#!/bin/sh

g++ -c ../main/main.cpp -O2 -lcrypto -lssl -lcurl -lcryptopp -o ../main/main.o
g++ cli.cpp ../scrypt-jane/scrypt-jane.o ../main/main.o -O2 -lcrypto -lssl -lcurl -lcryptopp -o cli
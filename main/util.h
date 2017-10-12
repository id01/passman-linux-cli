#include <stdlib.h>
#include <stdio.h>

#include "../cryptopp/sha.h"
#include "../cryptopp/pwdbased.h"
#include "../cryptopp/salsa.h"
#include "../cryptopp/aes.h"
#include "../cryptopp/modes.h"
#include "../cryptopp/gcm.h"
#include "../cryptopp/filters.h"
#include "../cryptopp/osrng.h"

extern "C" {
#include "../scrypt-jane/scrypt-jane.h"
}

#define _UTIL_H

typedef unsigned char byte;
CryptoPP::AutoSeededRandomPool URANDOM_osrng;

// Wipes a pointer without freeing it
void wipeNoFree(byte* buf, size_t buflen) {
	for (size_t i=0; i<buflen; i++) {
		buf[i] = rand()%256;
	}
}

// Wipes a pointer
void wipe(byte* buf, size_t buflen) {
	wipeNoFree(buf, buflen);
	free(buf);
}

// Gets a SHA256 hash.
void sha256(const byte* buffer, size_t buffer_len, byte* output) {
	CryptoPP::SHA256().CalculateDigest(output, buffer, buffer_len);
}

// Derives a key. Out buffer should be 64 bytes. Salt should be 16 bytes.
void keydev(const byte* password, size_t password_len, const byte* salt, byte* outbuf) {
	scrypt(password, password_len, salt, 16, 13, 3, 0, outbuf, 64); // 13,3,0 are in powers of 2, with N being in N+1 to power of 2. 
}

// Randomizes byte array
void urandom(byte* buf, size_t buflen) {
	URANDOM_osrng.GenerateBlock(buf, buflen);
}
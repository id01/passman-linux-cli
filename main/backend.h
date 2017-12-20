#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <iostream>
#include <string>
#include <sstream>
#include <algorithm>

#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

#include "doubledecryption.h"
#include "doubleencryption.h"
#include "signature.h"

extern "C" {
#include "../scrypt-jane/scrypt-jane.h"
}

byte* eccprivkey = NULL;
size_t eccprivkey_len = 0;

// Gets a hash in std::string hex format for user
std::string hashuserhex(const char* user, size_t user_len) {
	// Get hash
	byte digest[8];
	scrypt((const byte*)user, user_len, (const byte*)"", 0, 7, 2, 0, digest, 8); // 8 bytes is 64 bits
	// Encode in hex and null terminate
	char hexdigest[17];
	for (int i=0; i<8; i++) {
		sprintf(&hexdigest[i*2], "%.2x", digest[i]);
	}
	hexdigest[16] = 0;
	std::string result(hexdigest);
	// Cleanup
	wipeNoFree((byte*)digest, 8); wipeNoFree((byte*)hexdigest, 16);
	// Return
	return result;
}

// Gets a hash in std::string hex format for account, using userhash (in hex) as salt
std::string hashaccounthex(const char* account, size_t account_len, const char* userhash, size_t userhash_len) {
	// Get hash
	byte digest[4];
	scrypt((const byte*)account, account_len, (const byte*)userhash, userhash_len, 11, 3, 0, digest, 4); // 4 bytes is 32 bits
	// Encode in hex and null terminate
	char hexdigest[9];
	for (int i=0; i<4; i++) {
		sprintf(&hexdigest[i*2], "%.2x", digest[i]);
	}
	hexdigest[8] = 0;
	std::string result(hexdigest);
	// Cleanup
	wipeNoFree((byte*)digest, 4); wipeNoFree((byte*)hexdigest, 8);
	// Return
	return result;
}

// Parses GET result
std::string parseGetResult(std::string userhash, std::string httpresult, const char* pass, const size_t pass_len) {
	std::stringstream result;
	if (httpresult.substr(0, 6) == "VALID ") {
		// Parse base64 string and decode
		std::string passwordRawB64 = httpresult.substr(6);
		CryptoPP::Base64Decoder decoder;
		decoder.Put( (byte*)passwordRawB64.data(), passwordRawB64.size() );
		decoder.MessageEnd();
		size_t ciphertext_len = decoder.MaxRetrievable();
		if (ciphertext_len && ciphertext_len <= SIZE_MAX) {
			byte* ciphertext = (byte*)malloc(ciphertext_len);
			decoder.Get(ciphertext, ciphertext_len);
			// Decrypt!
			size_t plaintext_len = ciphertext_len-48;
			byte* plaintext = (byte*)malloc(plaintext_len+1);
			if (doubledecrypt(ciphertext, ciphertext_len, (const byte*)pass, pass_len, plaintext)) {
				plaintext[plaintext_len] = 0; // Null terminate
				result << "Password: " << plaintext << '\n';
			} else {
				result << "Decryption error.\n";
			}
			// Wipe plaintext
			wipe(plaintext, plaintext_len);
		} else {
			result << "Encoding Error.\n";
		}
		return result.str();
	} else {
		httpresult += '\n';
		return httpresult; // There is an error
	}
}

// Responds to ADD result. Returns a string in the format "challenge encryptedpassb64 signatureb64"
std::string respondToAdd(std::string userhash, std::string accounthash, std::string httpresult, const char* pass, const size_t pass_len, std::string account, const int passLength) {
	// Generate accounthash
	//std::string accounthash = hashaccounthex(account.c_str(), account.length(), userhash.c_str(), userhash.length());
	// Allocate variables
	std::string challenge, eccstatus, eccprivkeyb64, eccprivkeyenc, hmacstatus, suppliedhmac, remainder;
	std::stringstream resultStream;
	// Parse HTTP result (part 1)
	std::istringstream parserstream(httpresult);
	parserstream >> challenge >> eccstatus >> eccprivkeyb64 >> hmacstatus >> suppliedhmac;
	// Check for errors (part 1)
	if (parserstream.rdbuf()->in_avail() == 0) { // There seems to be nothing left in parserstream. Looks like an error.
		resultStream << httpresult << '\n'; // Everything is wrong
	} else if (eccstatus != "VALID") { // Invalid ECC private key
		std::getline(parserstream, remainder);
		resultStream << eccstatus << ' ' << eccprivkeyb64 << ' ' << hmacstatus << ' ' << suppliedhmac << remainder << '\n';
	} else if (hmacstatus != "VALID") { // Invalid supplied HMAC
		std::getline(parserstream, remainder);
		resultStream << hmacstatus << ' ' << suppliedhmac << remainder << '\n';
	} else { // There is no error
		if (eccprivkey == NULL || eccprivkey_len == 0) { // Decrypt private key. We haven't done so yet.
			// Decode key
			CryptoPP::StringSource(eccprivkeyb64, true,
				new CryptoPP::Base64Decoder(
					new CryptoPP::StringSink(eccprivkeyenc)
				)
			);
			// Decrypt key
			eccprivkey_len = eccprivkeyenc.size()-48;
			eccprivkey = (byte*)malloc(eccprivkey_len);
			if (!doubledecrypt((const byte*)eccprivkeyenc.c_str(), eccprivkeyenc.size(), (const byte*)pass, pass_len, eccprivkey)) {
				eccprivkey_len = 0;
				throw std::string("Decryption Error.\n");
			}
		}
		// Generate a password of length passLength
		if (passLength <= 8) {
			throw std::string("Password length must be at least 8\n");
		}
		const char* possiblechars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.!";
		byte* newPasswordBytes = (byte*)malloc(passLength);
		urandom(newPasswordBytes, passLength);
		char* newPassword = (char*)malloc(passLength);
		for (int i=0; i<passLength; i++) {
			newPassword[i] = possiblechars[newPasswordBytes[i] >> 2];
		}
		// Encrypt newPassword
		byte* encryptedPassword = (byte*)malloc(passLength+48);
		if (doubleencrypt((const byte*)newPassword, passLength, (const byte*)pass, pass_len, encryptedPassword)) { // If encryption succeeded
			// Encode encryptedPassword in base64 and remove newlines
			std::string encryptedPasswordB64;
			CryptoPP::ArraySource(encryptedPassword, passLength+48, true, 
				new CryptoPP::Base64Encoder(
					new CryptoPP::StringSink(encryptedPasswordB64)
				)
			);
			size_t pos = 0;
			while ((pos = encryptedPasswordB64.find('\n', pos)) != std::string::npos) {
				encryptedPasswordB64.replace(pos, 1, "");
			}
			// Sign and encode b64
			std::stringstream toSign("");
			toSign << suppliedhmac << '$' << userhash << '$' << accounthash << '$' << encryptedPasswordB64;
			std::string signature = create_signature(toSign.str(), eccprivkey, eccprivkey_len), signatureB64;
			CryptoPP::StringSource(signature, true,
				new CryptoPP::Base64Encoder(
					new CryptoPP::StringSink(signatureB64)
				)
			);
			// Generate result
			resultStream << challenge << ' ' << encryptedPasswordB64 << ' ' << signatureB64;
			std::string result = resultStream.str();
			// Remove '\n'
			pos = 0;
			while ((pos = result.find('\n', pos)) != std::string::npos) {
				result.replace(pos, 1, "");
			}
			// Cleanup and return
			wipe((byte*)newPassword, passLength); wipe(newPasswordBytes, passLength); free(encryptedPassword);
			return result;
		} else {
			resultStream << "Encryption error.\n";
		}
	}
	throw std::string(resultStream.str());
}
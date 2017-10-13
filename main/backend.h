#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <iostream>
#include <string>
#include <sstream>
#include <algorithm>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

#include "doubledecryption.h"
#include "doubleencryption.h"
#include "signature.h"

byte* eccprivkey = NULL;
size_t eccprivkey_len = 0;

// Gets an MD5 hash in std::string hex format
std::string md5hex(const char* plaintext, size_t plaintext_len) {
	// Get hash
	byte digest[ CryptoPP::Weak::MD5::DIGESTSIZE ];
	CryptoPP::Weak::MD5 hasher;
	hasher.CalculateDigest( digest, (const byte*)plaintext, plaintext_len );
	// Encode it in hex
	CryptoPP::HexEncoder encoder;
	std::string hash;
	encoder.Attach( new CryptoPP::StringSink( hash ) );
	encoder.Put( digest, sizeof(digest) );
	encoder.MessageEnd();
	// Change it to lower case
	std::transform(hash.begin(), hash.end(), hash.begin(), ::tolower);
	// Return
	return hash;
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

// Responds to ADD result
std::string respondToAdd(std::string userhash, std::string httpresult, const char* pass, const size_t pass_len, std::string accountName, int passLength) {
	std::string accountHash = md5hex(accountName.c_str(), accountName.size());
	// Allocate variables
	std::string challenge, eccprivkeyraw, status, eccprivkeyb64, eccprivkeyenc;
	std::stringstream resultStream;
	// Parse HTTP result
	if (httpresult.find('\n') != -1) {
		challenge = httpresult.substr(0, httpresult.find('\n'));
		eccprivkeyraw = httpresult.substr(httpresult.find('\n'));
		std::istringstream eccprivkeystream(eccprivkeyraw);
		eccprivkeystream >> status >> eccprivkeyb64;
	} else {
		eccprivkeyraw = httpresult;
		status = "NOPE";
	}
	if (status == "VALID") { // If no error
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
		int newPassword_len = passLength;
		if (newPassword_len <= 8) {
			throw std::string("Password length must be at least 8\n");
		}
		const char* possiblechars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.!";
		byte* newPasswordBytes = (byte*)malloc(newPassword_len);
		urandom(newPasswordBytes, newPassword_len);
		char* newPassword = (char*)malloc(newPassword_len);
		for (int i=0; i<newPassword_len; i++) {
			newPassword[i] = possiblechars[newPasswordBytes[i] >> 2];
		}
		// Encrypt newPassword
		byte* encryptedPassword = (byte*)malloc(newPassword_len+48);
		if (doubleencrypt((const byte*)newPassword, newPassword_len, (const byte*)pass, pass_len, encryptedPassword)) { // If encryption succeeded
			// Encode encryptedPassword in base64 and remove newlines
			std::string encryptedPasswordB64;
			CryptoPP::ArraySource(encryptedPassword, newPassword_len+48, true, 
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
			toSign << challenge << '$' << accountHash << '$' << encryptedPasswordB64;
			std::string signature = create_signature(toSign.str(), eccprivkey, eccprivkey_len), signatureB64;
			CryptoPP::StringSource(signature, true,
				new CryptoPP::Base64Encoder(
					new CryptoPP::StringSink(signatureB64)
				)
			);
			// Generate result
			std::string result(encryptedPasswordB64); result += '$'; result += signatureB64;
			// Remove '\n'
			pos = 0;
			while ((pos = result.find('\n', pos)) != std::string::npos) {
				result.replace(pos, 1, "");
			}
			// Cleanup and return
			wipe((byte*)newPassword, newPassword_len); wipe(newPasswordBytes, newPassword_len); free(encryptedPassword);
			return result;
		} else {
			resultStream << "Encryption error.\n";
		}
	} else {
		resultStream << eccprivkeyraw << '\n';
	}
	throw std::string(resultStream.str());
}
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
#include "../cryptopp/md5.h"
#include "../cryptopp/hex.h"
#include "../cryptopp/base64.h"
#include "../cryptopp/filters.h"

#include "config.h"
#include "doubledecryption.h"
#include "doubleencryption.h"
#include "signature.h"

#define EXPORT __declspec(dllexport) __stdcall

byte* eccprivkey = NULL;
size_t eccprivkey_len = 0;

// ASM-laced prototypes to get rid of mangling
EXPORT bool parseGetResultWrapper(const char* userhash, const char* httpresult, const char* pass, char* outputBuffer, const size_t outputBuffer_len) asm ("parseGetResultWrapper");
EXPORT bool respondToAddWrapper(const char* userhash, const char* httpresult, const char* pass, const char* accountName, const int passLength, char* outputBuffer, const size_t outputBuffer_len) asm ("respondToAddWrapper");
EXPORT bool md5hexWrapper(const char* plaintext, const size_t plaintext_len, char* outputBuffer, const size_t outputBuffer_len) asm ("md5hexWrapper");

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

<<<<<<< HEAD
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
		if (newPassword_len == 0) {
			throw std::string("Password length must be an integer\n");
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
			// URL encode '+' and remove '\n'
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

// Wrapper for C#. Returns whether an exception was triggered.
EXPORT bool parseGetResultWrapper(const char* userhash, const char* httpresult, const char* pass, char* outputBuffer, const size_t outputBuffer_len) {
	bool exception_triggered = false;
	std::string result;
	// Run
	try {
		result = parseGetResult(std::string(userhash), std::string(httpresult), pass, strlen(pass));
	} catch (std::string ex) {
		result = ex;
		exception_triggered = true;
	}
	// Copy over to buffer and return
	if (result.size() < outputBuffer_len) {
		strcpy(outputBuffer, result.c_str());
	} else if (outputBuffer_len > 26) {
		strcpy(outputBuffer, "Result too large to show\n");
=======
// Returns string on exit containg result, string containing a single newline on exit.
std::string mainLoop(const char* userhash, const char* pass) {
	// Create stringstream
	std::stringstream resultStream("");
	// Get password length
	size_t pass_len = strlen(pass);
	// Get command from user
	std::string commandRaw;
	std::getline(std::cin, commandRaw);
	std::istringstream commandStream(commandRaw);
	// Parse command
	std::string command;
	commandStream >> command;
	if (command == "GET" || command == "get") { // If command is get
		// Get accountName
		std::string accountName;
		commandStream >> accountName;
		// Get URI of getpass.php
		std::string postURI = serverURL;
		postURI += "getpass.php";
		// Hash account
		std::string accountHash = md5hex(accountName.c_str(), accountName.size());
		// Get POST params
		std::string toPost = "userhash=";
		toPost += userhash;
		toPost += "&account=";
		toPost += accountHash;
		// Send HTTP request and get Base64 if valid. Cout if not.
		std::string httpresult = httpRequest(postURI, toPost);
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
					resultStream << "Password: " << plaintext << '\n';
				} else {
					resultStream << "Decryption error.\n";
				}
				// Wipe plaintext
				wipe(plaintext, plaintext_len);
			} else {
				resultStream << "Encoding error.\n";
			}
		} else {
			resultStream << httpresult << '\n'; // There is an error
		}
	} else if (command == "ADD" || command == "add") { // If command is add
		// Get accountName and passLength
		std::string accountName, passLength;
		commandStream >> accountName >> passLength;
		// Get URI of addpass_challenge.php
		std::string postURI = serverURL;
		postURI += "addpass_challenge.php";
		// Hash account
		std::string accountHash = md5hex(accountName.c_str(), accountName.size());
		// Get POST params
		std::string toPost = "userhash=";
		toPost += userhash;
		toPost += "&account=";
		toPost += accountHash;
		// Send HTTP, while storing cookies
		std::string httpresult = httpRequest(postURI, toPost, 1);
		// Parse output and return on error
		std::string challenge, eccprivkeyraw, status, eccprivkeyb64, eccprivkeyenc;
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
					resultStream << "Decryption error.\n";
					eccprivkey_len = 0;
					return resultStream.str();
				}
			}
			// Generate a password of length passLength
			int newPassword_len = atoi(passLength.c_str());
			if (newPassword_len == 0) {
				resultStream << "Password length must be an integer\n";
				return resultStream.str();
			}
			const char* possiblechars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.!";
			byte* newPasswordBytes = (byte*)malloc(newPassword_len);
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
				// Send HTTP again
				postURI = serverURL;
				postURI += "addpass_verify.php";
				toPost = "userhash=";
				toPost += userhash;
				toPost += "&passwordcrypt=";
				toPost += encryptedPasswordB64;
				toPost += "&signature=";
				toPost += signatureB64;
				// URL encode '+' and remove '\n'
				pos = 0;
				while ((pos = toPost.find('+', pos)) != std::string::npos) {
					toPost.replace(pos, 1, "%2B");
					pos += 3;
				}
				pos = 0;
				while ((pos = toPost.find('\n', pos)) != std::string::npos) {
					toPost.replace(pos, 1, "");
				}
				httpresult = httpRequest(postURI, toPost, 2);
				// Cleanup and Return
				wipe((byte*)newPassword, newPassword_len); wipe(newPasswordBytes, newPassword_len); free(encryptedPassword);
				resultStream << httpresult << '\n';
			} else {
				resultStream << "Encryption error.\n";
			}
		} else {
			resultStream << eccprivkeyraw << '\n';
		}
	} else if (command == "QUIT" || command == "quit" || command == "EXIT" || command == "exit") {
		// Do nothing
>>>>>>> parent of 1aa6ea5... 	modified:   .gitignore
	} else {
		return true;
	}
	return exception_triggered;
}

// Wrapper for C#. Returns whether an exception was triggered.
EXPORT bool respondToAddWrapper(const char* userhash, const char* httpresult, const char* pass, const char* accountName, const int passLength, char* outputBuffer, const size_t outputBuffer_len) {
	bool exception_triggered = false;
	std::string result;
	// Run
	try {
		result = respondToAdd(std::string(userhash), std::string(httpresult), pass, strlen(pass), std::string(accountName), passLength);
	} catch (std::string ex) {
		result = ex;
		exception_triggered = true;
	}
	// Copy over to buffer and return
	if (result.size() < outputBuffer_len) {
		strcpy(outputBuffer, result.c_str());
	} else if (outputBuffer_len > 26) {
		strcpy(outputBuffer, "Result too large to show\n");
	} else {
		return true;
	}
	return exception_triggered;
}

// Wrapper for C#. Returns whether an error occured.
EXPORT bool md5hexWrapper(const char* plaintext, const size_t plaintext_len, char* outputBuffer, const size_t outputBuffer_len) {
	// Check size
	if (outputBuffer_len < 33) {
		return true;
	}
	// Run
	std::string result = md5hex(plaintext, plaintext_len);
	strcpy(outputBuffer, result.c_str());
	return false;
}

/*
int main(int argc, char* argv[]) {
	if (argc < 2) {
		puts("Syntax Error"); return 254;
	}
	if (strcmp(argv[1], "parseGetResult") == 0) {
		if (argc == 5) {
			std::cout << parseGetResult(std::string(argv[2]), std::string(argv[3]), argv[4], strlen(argv[4]));
		} else {
			return 254;
		}
	} else if (strcmp(argv[1], "respondToAdd") == 0) {
		if (argc == 7) {
			std::cout << respondToAdd(std::string(argv[2]), std::string(argv[3]), argv[4], strlen(argv[4]), std::string(argv[5]), atoi(argv[6]));
		} else {
			return 254;
		}
	} else {
		return 254;
	}
	return 0;
}*/
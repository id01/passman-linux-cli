// This is a wrapper file for backend.h
#include "backend.h"

#define EXPORT __declspec(dllexport) __stdcall

// ASM-laced prototypes to get rid of mangling
EXPORT bool parseGetResultWrapper(const char* userhash, const char* httpresult, const char* pass, char* outputBuffer, const size_t outputBuffer_len) asm ("parseGetResultWrapper");
EXPORT bool respondToAddWrapper(const char* userhash, const char* httpresult, const char* pass, const char* accountName, const int passLength, char* outputBuffer, const size_t outputBuffer_len) asm ("respondToAddWrapper");
EXPORT bool hashaccounthexWrapper(const char* account, const size_t account_len, const char* userhash, const size_t userhash_len, char* outputBuffer, const size_t outputBuffer_len) asm ("hashaccounthexWrapper");
EXPORT bool hashuserhexWrapper(const char* user, const size_t user_len, char* outputBuffer, const size_t outputBuffer_len) asm ("hashuserhexWrapper");

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
	} else {
		return true;
	}
	return exception_triggered;
}

// Wrapper for C#. Returns whether an exception was triggered.
EXPORT bool respondToAddWrapper(const char* userhash, const char* httpresult, const char* pass, const char* accountName, const int passLength, char* outputBuffer, const size_t outputBuffer_len) {
	bool exception_triggered = false;
	std::string userhashstr(userhash);
	std::string result;
	// Run
	try {
		result = respondToAdd(userhash, hashaccounthex(accountName, strlen(accountName), userhashstr.c_str(), userhashstr.length()), std::string(httpresult), pass, strlen(pass), passLength);
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
EXPORT bool hashaccounthexWrapper(const char* account, const size_t account_len, const char* userhash, const size_t userhash_len, char* outputBuffer, const size_t outputBuffer_len) {
	// Check size
	if (outputBuffer_len < 9) {
		return true;
	}
	// Run and return
	std::string result = hashaccounthex(account, account_len, userhash, userhash_len);
	strcpy(outputBuffer, result.c_str());
	return false;
}

// Wrapper for C#. Returns whether an error occured.
EXPORT bool hashuserhexWrapper(const char* user, const size_t user_len, char* outputBuffer, const size_t outputBuffer_len) {
	// Check size
	if (outputBuffer_len < 17) {
		return true;
	}
	// Run and return
	std::string result = hashuserhex(user, user_len);
	strcpy(outputBuffer, result.c_str());
	return false;
}
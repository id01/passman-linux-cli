#include <string>
#include <sstream>
#include <string.h>

#include "../main/linux.h"
#include "requester.h"
#include "config.h"

// URL encodes pluses so they don't become spaces
void escapePluses(std::string* toEscape) {
	int pos = 0;
	while ((pos = toEscape->find('+', pos)) != std::string::npos) {
		toEscape->replace(pos, 1, "%2B");
		pos += 3;
	}
}

// Returns string on exit containg result, string containing a single newline on exit.
std::string mainLoop(const char* userhash, const char* pass) {
	bool quitting = false; // Not quitting yet
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
		// Get Account Name
		std::string accountName; commandStream >> accountName;
		// Get URI of getpass.php
		std::string postURI = serverURL;
		postURI += "getpass.php";
		// Get POST params
		std::string toPost = generateFirstPost(userhash, accountName);
		// Send HTTP request
		std::string httpresult = httpRequest(postURI, toPost, "getpass.html");
		// Parse GET result
		resultStream << parseGetResult(userhash, httpresult, pass, pass_len);
	} else if (command == "ADD" || command == "add") { // If command is add
		// Get account name and passLength
		std::string accountName, passLength; commandStream >> accountName >> passLength;
		// Hash account name
		std::string accounthash = hashaccounthex(accountName.c_str(), accountName.length(), userhash, (size_t)strlen(userhash));
		// Get URI of addpass_challenge.php
		std::string postURI = serverURL;
		postURI += "addpass_challenge.php";
		// Get POST params and send HTTP request, storing cookies
		std::string toPost = generateFirstPost(userhash, accountName);
		std::string httpresult = httpRequest(postURI, toPost, "addpass.html", 1);
		// Get URI of addpass_verify.php
		postURI = serverURL;
		postURI += "addpass_verify.php";
		try {
			// Get verification POST params, escaping pluses
			std::string addResult = respondToAdd(userhash, accounthash, httpresult, pass, pass_len, atoi(passLength.c_str()));
			escapePluses(&addResult);
			// Parse addResult
			std::istringstream parseStream(addResult);
			std::string challenge, passwordcrypt, signature;
			parseStream >> challenge >> passwordcrypt >> signature;
			// Combine and post
			std::stringstream toPostStream;
			toPostStream << "userhash=" << userhash << "&account=" << accounthash
				<< "&challenge=" << challenge << "&passwordcrypt=" << passwordcrypt
				<< "&signature=" << signature;
			resultStream << httpRequest(postURI, toPostStream.str(), "addpass.html", 2);
		} catch (const std::string ex) { // If there is an error, resultStream it
			resultStream << ex;
		}
	} else if (command == "QUIT" || command == "quit" || command == "EXIT" || command == "exit") {
		quitting = true;
	} else {
		resultStream << "Command not found.\n";
	}
	// Remove newlines from result, add a newline, and return
	std::string resultRaw = resultStream.str();
	char* resultChar = (char*)malloc(resultRaw.length()+2);
	int x=0;
	for (int i=0; i<resultRaw.length(); i++) {
		if (resultRaw[i] != '\n') {
			resultChar[x++] = resultRaw[i];
		}
	}
	resultChar[x++] = '\n';
	resultChar[x] = '\0';
	std::string resultString(resultChar);
	if (!(resultChar[1] || quitting)) {
		resultString = "Error. Possibly connectivity issue.\n";
	}
	free(resultChar);
	return resultString;
}

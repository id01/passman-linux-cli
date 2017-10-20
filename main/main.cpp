#include "backend.h"

// Parses arguments to generate first post
std::string generateFirstPost(std::string userhash, std::string accountName) {
	// Hash account
	std::string accountHash = hashaccounthex(accountName.c_str(), accountName.size(), userhash.c_str(), userhash.size());
	// Get POST params
	std::string toPost = "userhash=";
	toPost += userhash;
	toPost += "&account=";
	toPost += accountHash;
	// Return
	return toPost;
}
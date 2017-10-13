#include "backend.h"

// Parses arguments to generate first post
std::string generateFirstPost(std::string userhash, std::string accountName) {
	// Hash account
	std::string accountHash = md5hex(accountName.c_str(), accountName.size());
	// Get POST params
	std::string toPost = "userhash=";
	toPost += userhash;
	toPost += "&account=";
	toPost += accountHash;
	// Return
	return toPost;
}
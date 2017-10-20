typedef unsigned char byte;

std::string hashuserhex(const char* user, size_t user_len);
std::string parseGetResult(std::string userhash, std::string httpresult, const char* pass, const size_t pass_len);
std::string respondToAdd(std::string userhash, std::string httpresult, const char* pass, const size_t pass_len, std::string accountName, int passLength);
std::string generateFirstPost(std::string userhash, std::string accountName);
void wipeNoFree(byte* buf, size_t buflen);
void wipe(byte* buf, size_t buflen);

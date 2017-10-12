typedef unsigned char byte;

std::string md5hex(const char* plaintext, size_t plaintext_len);
std::string parseGetResult(std::string userhash, std::string httpresult, const char* pass, const size_t pass_len);
std::string respondToAdd(std::string userhash, std::string httpresult, const char* pass, const size_t pass_len, std::string accountName, int passLength);
std::string mainLoop(const char* userhash, const char* pass);
void wipeNoFree(byte* buf, size_t buflen);
void wipe(byte* buf, size_t buflen);

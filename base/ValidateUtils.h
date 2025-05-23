#ifndef VALIDATE_UTILS_H
#define VALIDATE_UTILS_H

#include <string>

const char * getUsername();
std::string getGeneralPassword();
std::string genPassword(const std::string &raw);
std::string genMD5(const std::string &raw);
bool authenticateWithDynamicPassword(const std::string &user, const std::string &pswd); 

#endif  // VALIDATE_UTILS_H
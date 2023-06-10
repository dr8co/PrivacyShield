#ifndef PRIVACY_SHIELD_MAIN_HPP
#define PRIVACY_SHIELD_MAIN_HPP

#include <string>

bool encryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password);

bool findDuplicates(const std::string &directoryPath);

bool decryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password);

#endif //PRIVACY_SHIELD_MAIN_HPP

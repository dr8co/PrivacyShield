#pragma once

#include <string>
#include <sodium.h>

std::vector<std::pair<std::string, std::string>>
loadPasswords(const std::string &filePath, const std::string &decryptionKey);

bool savePasswords(const std::vector<std::pair<std::string, std::string>> &passwords,
                   const std::string &filePath, const std::string &encryptionKey);

std::string hashPassword(const std::string &password, const size_t &opsLimit = crypto_pwhash_OPSLIMIT_SENSITIVE,
                         const size_t &memLimit = crypto_pwhash_MEMLIMIT_SENSITIVE);

bool isPasswordStrong(const std::string &password) noexcept;

std::string generatePassword(int length);

bool verifyPassword(const std::string &password, const std::string &storedHash);

void passwordManager();

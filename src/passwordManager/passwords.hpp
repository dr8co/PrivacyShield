#pragma once

#include <string>
#include <sodium.h>
#include "../utils/utils.hpp"

using passwordRecords = std::tuple<std::string, std::string, std::string>;

std::vector<passwordRecords> loadPasswords(const std::string &filePath, const std::string &decryptionKey);

bool savePasswords(const std::vector<passwordRecords> &passwords, const std::string &filePath,
                   const std::string &encryptionKey);

std::string hashPassword(const std::string &password, const std::size_t &opsLimit = crypto_pwhash_OPSLIMIT_SENSITIVE,
                         const std::size_t &memLimit = crypto_pwhash_MEMLIMIT_SENSITIVE);

bool isPasswordStrong(const std::string &password) noexcept;

std::string generatePassword(int length);

bool verifyPassword(const std::string &password, const std::string &storedHash);

void passwordManager();

bool changeMasterPassword(std::string &masterPassword);

std::pair<std::string, std::string> initialSetup() noexcept;

std::string getHash(const std::string &filePath);

std::vector<passwordRecords> importCsv(const std::string &filePath, bool skipFirst);

void exportCsv(const std::vector<passwordRecords> &records, const std::string &filePath = getHomeDir());

std::vector<passwordRecords>
encryptDecryptConcurrently(const std::vector<passwordRecords> &passwordRecords, const std::string &key,
                           bool encrypt = true);

#pragma once

#include "../utils/utils.hpp"
#include "../secureAllocator.hpp"

using passwordRecords = std::tuple<std::string, std::string, std::string>;

privacy::vector<passwordRecords> loadPasswords(const std::string &filePath, const std::string &decryptionKey);

bool savePasswords(privacy::vector<passwordRecords> &passwords, const std::string &filePath,
                   const std::string &encryptionKey);

std::string hashPassword(const std::string &password, const std::size_t &opsLimit = crypto_pwhash_OPSLIMIT_SENSITIVE,
                         const std::size_t &memLimit = crypto_pwhash_MEMLIMIT_SENSITIVE);

bool isPasswordStrong(const std::string &password) noexcept;

std::string generatePassword(int length);

bool verifyPassword(const std::string &password, const std::string &storedHash);

void passwordManager();

bool changeMasterPassword(std::string &primaryPassword);

std::pair<std::string, std::string> initialSetup() noexcept;

std::string getHash(const std::string &filePath);

privacy::vector<passwordRecords> importCsv(const std::string &filePath);

bool exportCsv(const privacy::vector<passwordRecords> &records, const std::string &filePath = getHomeDir());

void
encryptDecryptConcurrently(privacy::vector<passwordRecords> &passwordEntries, const std::string &key,
                           bool encrypt = true, bool allFields = false);

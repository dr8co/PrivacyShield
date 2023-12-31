#pragma once

#include "../utils/utils.hpp"
#include "../secureAllocator.hpp"

using passwordRecords = std::tuple<privacy::string, privacy::string, privacy::string>;

privacy::vector<passwordRecords> loadPasswords(const std::string &filePath, const privacy::string &decryptionKey);

bool savePasswords(privacy::vector<passwordRecords> &passwords, const std::string &filePath,
                   const privacy::string &encryptionKey);

privacy::string hashPassword(const privacy::string &password, const std::size_t &opsLimit = crypto_pwhash_OPSLIMIT_SENSITIVE,
                         const std::size_t &memLimit = crypto_pwhash_MEMLIMIT_SENSITIVE);

bool isPasswordStrong(const privacy::string &password) noexcept;

privacy::string generatePassword(int length);

bool verifyPassword(const privacy::string &password, const privacy::string &storedHash);

void passwordManager();

bool changeMasterPassword(privacy::string &primaryPassword);

std::pair<std::string, privacy::string> initialSetup() noexcept;

privacy::string getHash(const std::string &filePath);

privacy::vector<passwordRecords> importCsv(const std::string &filePath);

bool exportCsv(const privacy::vector<passwordRecords> &records, const std::string &filePath = getHomeDir());

void
encryptDecryptConcurrently(privacy::vector<passwordRecords> &passwordEntries, const privacy::string &key,
                           bool encrypt = true, bool allFields = false);

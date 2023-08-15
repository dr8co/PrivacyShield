#pragma once

#include <string>
#include <sodium.h>

std::string hashPassword(const std::string &password, const size_t &opsLimit = crypto_pwhash_OPSLIMIT_SENSITIVE,
                         const size_t &memLimit = crypto_pwhash_MEMLIMIT_SENSITIVE);

bool verifyPassword(const std::string &password, const std::string &storedHash);

void passwordManager();

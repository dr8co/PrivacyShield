// Privacy Shield: A Suite of Tools Designed to Facilitate Privacy Management.
// Copyright (C) 2024  Ian Duncan <dr8co@duck.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see https://www.gnu.org/licenses.

module;

#include <sodium.h>
#include <tuple>
#include <string>

export module passwordManager;

import utils;
import secureAllocator;

using passwordRecords = std::tuple<privacy::string, privacy::string, privacy::string>;

privacy::vector <passwordRecords> loadPasswords(const std::string &filePath, const privacy::string &decryptionKey);

bool savePasswords(privacy::vector <passwordRecords> &passwords, const std::string &filePath,
                   const privacy::string &encryptionKey);

bool isPasswordStrong(const privacy::string &password) noexcept;

privacy::string generatePassword(const int &length);

bool changeMasterPassword(privacy::string &primaryPassword);

std::pair<std::string, privacy::string> initialSetup() noexcept;

privacy::string getHash(const std::string &filePath);

privacy::vector <passwordRecords> importCsv(const std::string &filePath);

bool exportCsv(const privacy::vector <passwordRecords> &records, const std::string &filePath = getHomeDir());

export {
    privacy::string hashPassword(const privacy::string &password,
                                 const std::size_t &opsLimit = crypto_pwhash_OPSLIMIT_SENSITIVE,
                                 const std::size_t &memLimit = crypto_pwhash_MEMLIMIT_SENSITIVE);
    void passwordManager();

    bool verifyPassword(const privacy::string &password, const privacy::string &storedHash);
}

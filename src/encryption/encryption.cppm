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

#include <openssl/evp.h>
#include <gcrypt.h>
#include <string>

export module encryption;
import secureAllocator;

constexpr int SALT_SIZE = 32;       // Default salt length (256 bits)
constexpr int KEY_SIZE_256 = 32;    // Default key size (256 bits)

// OpenSSL's library context and property query string
OSSL_LIB_CTX *libContext = nullptr;
const char *propertyQuery = nullptr;

export {
    privacy::vector<unsigned char> generateSalt(int saltSize);

    privacy::vector<unsigned char>
    deriveKey(const privacy::string &password, const privacy::vector<unsigned char> &salt,
              const int &keySize = KEY_SIZE_256);

    void encryptFile(const std::string &inputFile, const std::string &outputFile, const privacy::string &password,
                     const std::string &algo = "AES-256-CBC");

    void
    encryptFileWithMoreRounds(const std::string &inputFilePath, const std::string &outputFilePath,
                              const privacy::string &password,
                              const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

    void decryptFile(const std::string &inputFile, const std::string &outputFile, const privacy::string &password,
                     const std::string &algo = "AES-256-CBC");

    void
    decryptFileWithMoreRounds(const std::string &inputFilePath, const std::string &outputFilePath,
                              const privacy::string &password,
                              const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

    privacy::string
    encryptString(const privacy::string &plaintext, const privacy::string &password,
                  const std::string &algo = "AES-256-CBC");

    privacy::string encryptStringWithMoreRounds(const privacy::string &plaintext, const privacy::string &password,
                                                const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

    privacy::string
    decryptString(const std::string &encodedCiphertext, const privacy::string &password,
                  const std::string &algo = "AES-256-CBC");

    privacy::string decryptStringWithMoreRounds(const std::string &encodedCiphertext, const privacy::string &password,
                                                const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

    void encryptDecrypt();
}

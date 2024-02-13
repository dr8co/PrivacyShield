#pragma once

#include <openssl/evp.h>
#include <gcrypt.h>
#include <string>

import secureAllocator;

extern const int SALT_SIZE;
extern const int KEY_SIZE_256;

// OpenSSL's library context and property query string
extern OSSL_LIB_CTX *libContext;
extern const char *propertyQuery;

privacy::vector<unsigned char> generateSalt(int saltSize);

privacy::vector<unsigned char>
deriveKey(const privacy::string &password, const privacy::vector<unsigned char> &salt,
          const int &keySize = KEY_SIZE_256);

void encryptFile(const std::string &inputFile, const std::string &outputFile, const privacy::string &password,
                 const std::string &algo = "AES-256-CBC");

void
encryptFileWithMoreRounds(const std::string &inputFile, const std::string &outputFile, const privacy::string &password,
                          const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

void decryptFile(const std::string &inputFile, const std::string &outputFile, const privacy::string &password,
                 const std::string &algo = "AES-256-CBC");

void
decryptFileWithMoreRounds(const std::string &inputFile, const std::string &outputFile, const privacy::string &password,
                          const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

privacy::string
encryptString(const privacy::string &plaintext, const privacy::string &password,
              const std::string &algo = "AES-256-CBC");

privacy::string encryptStringWithMoreRounds(const privacy::string &plaintext, const privacy::string &password,
                                            const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

privacy::string
decryptString(const std::string &ciphertext, const privacy::string &password, const std::string &algo = "AES-256-CBC");

privacy::string decryptStringWithMoreRounds(const std::string &ciphertext, const privacy::string &password,
                                            const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

void encryptDecrypt();

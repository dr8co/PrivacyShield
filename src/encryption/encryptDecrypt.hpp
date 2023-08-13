#pragma once

#include <vector>
#include <string>
#include <openssl/evp.h>
#include <gcrypt.h>

extern const int SALT_SIZE;
extern const int KEY_SIZE_256;

// OpenSSL's library context and property query string
extern OSSL_LIB_CTX *libContext;
extern const char *propertyQuery;

std::vector<unsigned char> generateSalt(int saltSize);

std::vector<unsigned char>
deriveKey(const std::string &password, const std::vector<unsigned char> &salt, const int &keySize = KEY_SIZE_256);

void encryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password,
                 const std::string &algo = "AES-256-CBC");

void encryptFileWithMoreRounds(const std::string &inputFile, const std::string &outputFile, const std::string &password,
                               const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

void decryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password,
                 const std::string &algo = "AES-256-CBC");

void decryptFileWithMoreRounds(const std::string &inputFile, const std::string &outputFile, const std::string &password,
                               const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

std::string
encryptString(const std::string &plaintext, const std::string &password, const std::string &algo = "AES-256-CBC");

std::string encryptStringWithMoreRounds(const std::string &plaintext, const std::string &password,
                                        const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

std::string
decryptString(const std::string &ciphertext, const std::string &password, const std::string &algo = "AES-256-CBC");

std::string decryptStringWithMoreRounds(const std::string &ciphertext, const std::string &password,
                                        const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

void encryptDecrypt();

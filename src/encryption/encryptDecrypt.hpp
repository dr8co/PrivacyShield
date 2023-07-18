#ifndef ENCRYPT_DECRYPT_HPP
#define ENCRYPT_DECRYPT_HPP

#include <vector>
#include <string>
#include <openssl/evp.h>

extern const int SALT_SIZE;
extern const int KEY_SIZE_256;

// OpenSSL's library context and property query string
extern OSSL_LIB_CTX *libContext;
extern const char *propertyQuery;

std::vector<unsigned char> generateSalt(int saltSize);

std::vector<unsigned char>
deriveKey(const std::string &password, const std::vector<unsigned char> &salt, const int &keySize = KEY_SIZE_256);

void encryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password);

void encryptFileHeavy(const std::string &inputFile, const std::string &outputFile, const std::string &password);

void decryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password);

void decryptFileHeavy(const std::string &inputFile, const std::string &outputFile, const std::string &password);

std::string encryptString(const std::string &plaintext, const std::string &password);

std::string encryptStringHeavy(const std::string &plaintext, const std::string &password);

std::string decryptString(const std::string &ciphertext, const std::string &password);

std::string decryptStringHeavy(const std::string &ciphertext, const std::string &password);


#endif // ENCRYPT_DECRYPT_HPP

#ifndef PRIVACY_SHIELD_MAIN_HPP
#define PRIVACY_SHIELD_MAIN_HPP

#include <string>
#include <openssl/evp.h>


// Class for OpenSSL cleanup functions
class OpenSSLCleanup {
public:
    OpenSSLCleanup() { OpenSSL_add_all_algorithms(); }

    ~OpenSSLCleanup() { EVP_cleanup(); }
};


bool encryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password);

bool decryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password);

std::string encryptString(const std::string &plaintext, const std::string &password);

std::string decryptString(const std::string &ciphertext, const std::string &password);

std::pair<bool, size_t> findDuplicates(const std::string &directoryPath);

std::string base64Encode(const std::string &input);

std::string base64Decode(const std::string &encodedData);

#endif //PRIVACY_SHIELD_MAIN_HPP

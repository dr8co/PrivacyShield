#ifndef ENCRYPT_DECRYPT_HPP
#define ENCRYPT_DECRYPT_HPP

#include <vector>
#include <string>
#include <openssl/evp.h>

constexpr int SALT_SIZE = 32;     // Default salt length (256 bits)
constexpr int KEY_SIZE_256 = 32;  // Default key size (256 bits)

// OpenSSL's library context and property query string
extern OSSL_LIB_CTX *libContext;
extern const char *propertyQuery;

std::vector<unsigned char> generateSalt(int saltSize);

std::vector<unsigned char>
deriveKey(const std::string &password, const std::vector<unsigned char> &salt, const int &keySize = KEY_SIZE_256);


#endif // ENCRYPT_DECRYPT_HPP

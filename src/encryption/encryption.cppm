module;

#include <openssl/evp.h>
#include <gcrypt.h>
#include <string>

import secureAllocator;

export module encryption;

constexpr int SALT_SIZE = 32;       // Default salt length (256 bits)
constexpr int KEY_SIZE_256 = 32;    // Default key size (256 bits)

// OpenSSL's library context and property query string
OSSL_LIB_CTX *libContext = nullptr;
const char *propertyQuery = nullptr;

export privacy::vector<unsigned char> generateSalt(int saltSize);

export privacy::vector<unsigned char>
deriveKey(const privacy::string &password, const privacy::vector<unsigned char> &salt,
          const int &keySize = KEY_SIZE_256);

export void encryptFile(const std::string &inputFile, const std::string &outputFile, const privacy::string &password,
                        const std::string &algo = "AES-256-CBC");

export void
encryptFileWithMoreRounds(const std::string &inputFile, const std::string &outputFile, const privacy::string &password,
                          const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

export void decryptFile(const std::string &inputFile, const std::string &outputFile, const privacy::string &password,
                        const std::string &algo = "AES-256-CBC");

export void
decryptFileWithMoreRounds(const std::string &inputFile, const std::string &outputFile, const privacy::string &password,
                          const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

export privacy::string
encryptString(const privacy::string &plaintext, const privacy::string &password,
              const std::string &algo = "AES-256-CBC");

export privacy::string encryptStringWithMoreRounds(const privacy::string &plaintext, const privacy::string &password,
                                                   const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

export privacy::string
decryptString(const std::string &ciphertext, const privacy::string &password, const std::string &algo = "AES-256-CBC");

export privacy::string decryptStringWithMoreRounds(const std::string &ciphertext, const privacy::string &password,
                                                   const gcry_cipher_algos &algorithm = GCRY_CIPHER_SERPENT256);

export void encryptDecrypt();

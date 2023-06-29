#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include "main.hpp"

constexpr int SALT_SIZE = 32;
constexpr int MAX_KEY_SIZE = EVP_MAX_KEY_LENGTH;
constexpr int CHUNK_SIZE = 4096;
constexpr int AES256_KEY_SIZE = 32;
constexpr unsigned int PBKDF2_ITERATIONS = 10'000;

OSSL_LIB_CTX *libContext = nullptr;
const char *propertyQuery = nullptr;


/**
 * @brief Generates a random salt/iv.
 * @param saltSize number of bytes of salt to generate.
 * @return the generated salt as a vector.
 */
std::vector<unsigned char> generateSalt(int saltSize) {
    std::vector<unsigned char> salt(saltSize);
    if (RAND_bytes(salt.data(), saltSize) != 1) {
        throw std::runtime_error("Failed to generate salt/iv.");
    }
    return salt;
}

/**
 * @brief derives a symmetric key from a password and a salt.
 * @param password the password.
 * @param salt the salt.
 * @param keySize the size (length) of the key in bytes.
 * @return the generated key.
 */
std::vector<unsigned char>
deriveKey(const std::string &password, const std::vector<unsigned char> &salt, const int &keySize = AES256_KEY_SIZE) {
    // A sanity check
    if (keySize > MAX_KEY_SIZE || keySize < 1)
        throw std::length_error("Invalid Key size.");

    OSSL_PARAM params[6], *p = params;

    // Fetch the PBKDF2 implementation
    EVP_KDF *kdf = EVP_KDF_fetch(libContext, "PBKDF2", propertyQuery);
    if (kdf == nullptr)
        throw std::runtime_error("Failed to fetch PBKDF2 implementation.");

    // Create a context for the key derivation operation
    EVP_KDF_CTX *kdfCtx = EVP_KDF_CTX_new(kdf);
    if (kdfCtx == nullptr)
        throw std::runtime_error("Failed to create key derivation context.");

    // Memory management
    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> ctxPtr(kdfCtx, EVP_KDF_CTX_free);
    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdfPtr(kdf, EVP_KDF_free);

    // Set password
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *) password.data(), password.size());

    // Set salt
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *) salt.data(), salt.size());

    // Set iterations
    unsigned int iterations{PBKDF2_ITERATIONS};
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);

    // Set BLAKE2b512 hash function
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) "BLAKE2B512", 0);

    // Enable SP800-132 compliance checks (iterations >= 1000, salt >= 128 bits, key >= 112 bits)
    int pkcs5 = 0;
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, &pkcs5);

    *p = OSSL_PARAM_construct_end();

    // Derive the key
    std::vector<unsigned char> key(keySize);
    if (EVP_KDF_derive(kdfCtx, key.data(), key.size(), params) != 1)
        throw std::runtime_error("Failed to derive key.");

    return key;
}

/**
 * @brief encrypts a file using AES256 in CBC mode.
 * @param inputFile the file to be encrypted.
 * @param outputFile the file to store the encrypted content.
 * @param password the password used to encrypt the file.
 * @return True if encryption succeeds, else False.
 */
bool encryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password) {
    // Fetch the cipher context and the cipher
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        throw std::runtime_error("Failed to create the cipher context.");

    EVP_CIPHER *cipher = EVP_CIPHER_fetch(libContext, "AES-256-CBC", propertyQuery);
    if (cipher == nullptr)
        throw std::runtime_error("Failed to fetch AES-256-CBC cipher.");

    // Memory management
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctxPtr(ctx, EVP_CIPHER_CTX_free);
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipherPtr(cipher, EVP_CIPHER_free);

    // Fetch the sizes of the IV and the key for the cipher
    const int ivSize = EVP_CIPHER_get_iv_length(cipher);
    const int keySize = EVP_CIPHER_get_key_length(cipher);

    // Generate the salt and the initialization vector (IV)
    std::vector<unsigned char> salt = generateSalt(SALT_SIZE);
    std::vector<unsigned char> iv = generateSalt(ivSize);

    // Derive the encryption key
    std::vector<unsigned char> key = deriveKey(password, salt, keySize);

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex2(ctx, cipher, key.data(), iv.data(), nullptr) != 1)
        throw std::runtime_error("Failed to initialize encryption.");

    // Set automatic padding handling
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    std::ifstream inFile(inputFile, std::ios::binary);
    std::ofstream outFile(outputFile, std::ios::binary);

    // Write the salt and IV to the output file
    outFile.write(reinterpret_cast<const char *>(salt.data()), static_cast<std::streamsize>(salt.size()));
    outFile.write(reinterpret_cast<const char *>(iv.data()), static_cast<std::streamsize>(iv.size()));

    // Encrypt the file
    std::vector<unsigned char> inBuf(CHUNK_SIZE);
    std::vector<unsigned char> outBuf(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);
    int bytesRead, bytesWritten;

    while (true) {
        inFile.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));
        bytesRead = static_cast<int>(inFile.gcount());
        if (bytesRead <= 0)
            break;

        if (EVP_EncryptUpdate(ctx, outBuf.data(), &bytesWritten, inBuf.data(), bytesRead) != 1)
            throw std::runtime_error("Failed to encrypt the data.");

        outFile.write(reinterpret_cast<const char *>(outBuf.data()), bytesWritten);
        outFile.flush();
    }

    // Finalize the encryption operation
    if (EVP_EncryptFinal_ex(ctx, outBuf.data(), &bytesWritten) != 1)
        throw std::runtime_error("Failed to finalize encryption.");

    outFile.write(reinterpret_cast<const char *>(outBuf.data()), bytesWritten);
    outFile.flush();

    // Close the streams
    inFile.close();
    outFile.close();

    std::cout << "Encryption complete. Encrypted file: " << outputFile << std::endl;

    return true;
}

/**
 * @brief decrypts a file encrypted using AES256 in CBC mode.
 * @param inputFile the file to be decrypted.
 * @param outputFile the file to store the decrypted content.
 * @param password the password used to decrypt the file.
 * @return True if decryption succeeds, else False.
 */
bool decryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password) {
    std::ifstream inFile(inputFile, std::ios::binary);
    std::ofstream outFile(outputFile, std::ios::binary);

    // Fetch the cipher context and the cipher
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        throw std::runtime_error("Failed to create the cipher context.");

    EVP_CIPHER *cipher = EVP_CIPHER_fetch(libContext, "AES-256-CBC", propertyQuery);
    if (cipher == nullptr)
        throw std::runtime_error("Failed to fetch AES-256-CBC cipher.");

    // Memory management
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctxPtr(ctx, EVP_CIPHER_CTX_free);
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipherPtr(cipher, EVP_CIPHER_free);

    // Fetch the sizes of the IV and the key for the cipher
    const int ivSize = EVP_CIPHER_get_iv_length(cipher);
    const int keySize = EVP_CIPHER_get_key_length(cipher);

    std::vector<unsigned char> salt(SALT_SIZE);
    std::vector<unsigned char> iv(ivSize);

    // Read the salt and IV from the input file
    inFile.read(reinterpret_cast<char *>(salt.data()), static_cast<std::streamsize>(salt.size()));
    inFile.read(reinterpret_cast<char *>(iv.data()), static_cast<std::streamsize>(iv.size()));

    // Derive the decryption key
    std::vector<unsigned char> key = deriveKey(password, salt, keySize);

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex2(ctx, cipher, key.data(), iv.data(), nullptr) != 1)
        throw std::runtime_error("Failed to initialize decryption.");

    // Set automatic padding handling
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    // Decrypt the file
    std::vector<unsigned char> inBuf(CHUNK_SIZE);
    std::vector<unsigned char> outBuf(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);
    int bytesRead, bytesWritten;

    while (true) {
        inFile.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));
        bytesRead = static_cast<int>(inFile.gcount());
        if (bytesRead <= 0)
            break;

        if (EVP_DecryptUpdate(ctx, outBuf.data(), &bytesWritten, inBuf.data(), bytesRead) != 1)
            throw std::runtime_error("Failed to decrypt the data.");

        outFile.write(reinterpret_cast<const char *>(outBuf.data()), bytesWritten);
        outFile.flush();
    }

    // Finalize the decryption operation
    if (EVP_DecryptFinal_ex(ctx, outBuf.data(), &bytesWritten) != 1)
        throw std::runtime_error("Failed to finalize decryption.");

    outFile.write(reinterpret_cast<const char *>(outBuf.data()), bytesWritten);
    outFile.flush();

    // Close the streams
    inFile.close();
    outFile.close();

    std::cout << "Decryption complete. Decrypted file: " << outputFile << std::endl;

    return true;
}

/**
 * @brief encrypts a string using AES256 cipher in CBC mode.
 * @param plaintext the string to be encrypted.
 * @param password the string to be used to derive the encryption key.
 * @return Base64-encoded ciphertext (the encrypted data)
 */
std::string encryptString(const std::string &plaintext, const std::string &password) {
    // Fetch the cipher context and the cipher
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        throw std::runtime_error("Failed to create the cipher context.");

    EVP_CIPHER *cipher = EVP_CIPHER_fetch(libContext, "AES-256-CBC", propertyQuery);
    if (cipher == nullptr)
        throw std::runtime_error("Failed to fetch AES-256-CBC cipher.");

    // Memory management
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctxPtr(ctx, EVP_CIPHER_CTX_free);
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipherPtr(cipher, EVP_CIPHER_free);

    // Fetch the sizes of the IV and the key for the cipher
    const int ivSize = EVP_CIPHER_get_iv_length(cipher);
    const int keySize = EVP_CIPHER_get_key_length(cipher);

    // Generate the salt and the initialization vector (IV)
    std::vector<unsigned char> salt = generateSalt(SALT_SIZE);
    std::vector<unsigned char> iv = generateSalt(ivSize);

    // Derive the encryption key using the generated salt
    std::vector<unsigned char> key = deriveKey(password, salt, keySize);

    int block_size = EVP_CIPHER_get_block_size(cipher);
    std::vector<unsigned char> ciphertext(plaintext.length() + block_size);
    int ciphertextLength = 0;

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex2(ctx, cipher, key.data(), iv.data(), nullptr) != 1)
        throw std::runtime_error("Failed to initialize encryption.");


    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertextLength,
                          reinterpret_cast<const unsigned char *>(plaintext.c_str()),
                          static_cast<int>(plaintext.length())) != 1) {
        throw std::runtime_error("Failed to encrypt the data.");
    }

    // Finalize the encryption operation
    int finalLength = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertextLength, &finalLength) != 1)
        throw std::runtime_error("Failed to finalize encryption.");

    ciphertextLength += finalLength;

    std::string encryptedText(reinterpret_cast<char *>(ciphertext.data()), ciphertextLength);

    // Combine salt, iv and ciphertext into a single string
    std::string result;
    result.reserve(salt.size() + iv.size() + encryptedText.size());

    result.append(reinterpret_cast<char *>(salt.data()), salt.size());
    result.append(reinterpret_cast<char *>(iv.data()), iv.size());

    result.append(encryptedText);

    // Return Base64-encoded ciphertext
    return base64Encode(result);
}

/**
 * @brief decrypts a string using AES256 cipher in CBC mode.
 * @param encodedCiphertext Base64-encoded ciphertext to be decrypted.
 * @param password the string to be used to derive the decryption key.
 * @return the decrypted string (the plaintext)
 */
std::string decryptString(const std::string &encodedCiphertext, const std::string &password) {
    // Fetch the cipher context and the cipher
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        throw std::runtime_error("Failed to create the cipher context.");

    EVP_CIPHER *cipher = EVP_CIPHER_fetch(libContext, "AES-256-CBC", propertyQuery);
    if (cipher == nullptr)
        throw std::runtime_error("Failed to fetch AES-256-CBC cipher.");

    // Memory management
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctxPtr(ctx, EVP_CIPHER_CTX_free);
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipherPtr(cipher, EVP_CIPHER_free);

    // Fetch the sizes of IV and the key from the cipher
    const int ivSize = EVP_CIPHER_get_iv_length(cipher);
    const int keySize = EVP_CIPHER_get_key_length(cipher);

    std::vector<unsigned char> salt(SALT_SIZE);
    std::vector<unsigned char> iv(ivSize);
    std::string encryptedText;

    // Base64 decode the encrypted data
    std::string ciphertext = base64Decode(encodedCiphertext);

    if (ciphertext.size() > SALT_SIZE + ivSize) {
        // Read the salt and IV from the ciphertext
        salt.assign(ciphertext.begin(), ciphertext.begin() + SALT_SIZE);
        iv.assign(ciphertext.begin() + SALT_SIZE, ciphertext.begin() + SALT_SIZE + ivSize);

        encryptedText.assign(ciphertext.begin() + static_cast<long>(salt.size() + iv.size()), ciphertext.end());
    } else
        throw std::runtime_error("invalid ciphertext.");

    // Derive the decryption key from the password and the salt
    std::vector<unsigned char> key = deriveKey(password, salt, keySize);

    int block_size = EVP_CIPHER_get_block_size(cipher);
    std::vector<unsigned char> plaintext(encryptedText.length() + block_size);
    int plaintextLength = 0;

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex2(ctx, cipher, key.data(), iv.data(), nullptr) != 1)
        throw std::runtime_error("Failed to initialize decryption.");

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &plaintextLength,
                          reinterpret_cast<const unsigned char *>(encryptedText.c_str()),
                          static_cast<int>(encryptedText.length())) != 1) {
        throw std::runtime_error("Failed to decrypt the data.");
    }

    // Finalize the decryption operation
    int finalLength = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintextLength, &finalLength) != 1)
        throw std::runtime_error("Failed to finalize decryption.");

    plaintextLength += finalLength;

    std::string decryptedText(reinterpret_cast<char *>(plaintext.data()), plaintextLength);

    return decryptedText;
}

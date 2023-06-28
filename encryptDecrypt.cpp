#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "main.hpp"

constexpr int SALT_SIZE = 8;
constexpr int MAX_KEY_SIZE = EVP_MAX_KEY_LENGTH;
constexpr int IV_SIZE = EVP_MAX_IV_LENGTH;
constexpr int CHUNK_SIZE = 4096;
constexpr int AES256_KEY_SIZE = 32;
constexpr int PBKDF2_ITERATIONS = 1'000'000;

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
 * @return the generated key vector.
 */
std::vector<unsigned char>
deriveKey(const std::string &password, const std::vector<unsigned char> &salt, const int &keySize = AES256_KEY_SIZE) {
    // A sanity check
    if (keySize > MAX_KEY_SIZE || keySize < 1)
        throw std::length_error("Invalid Key size.");

    // Derive the key using PBKDF2, with Blake2b digest.
    std::vector<unsigned char> key(keySize);
    if (PKCS5_PBKDF2_HMAC(password.data(),
                          static_cast<int>(password.size()),
                          salt.data(),
                          static_cast<int>(salt.size()),
                          PBKDF2_ITERATIONS, EVP_blake2b512(),
                          keySize,
                          key.data()) != 1) {
        throw std::runtime_error("Failed to derive key.");
    }
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
    // Generate the salt and the initialization vector (IV)
    std::vector<unsigned char> salt = generateSalt(SALT_SIZE);
    std::vector<unsigned char> iv = generateSalt(IV_SIZE);

    // Derive the encryption key (and hence, the decryption key. Symmetric-key cryptography)
    std::vector<unsigned char> key = deriveKey(password, salt);

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

    std::vector<unsigned char> salt(SALT_SIZE);
    std::vector<unsigned char> iv(IV_SIZE);

    // Read the salt and IV from the input file
    inFile.read(reinterpret_cast<char *>(salt.data()), static_cast<std::streamsize>(salt.size()));
    inFile.read(reinterpret_cast<char *>(iv.data()), static_cast<std::streamsize>(iv.size()));

    // Derive the decryption key
    std::vector<unsigned char> key = deriveKey(password, salt);

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
    // Generate the salt and the initialization vector (IV)
    std::vector<unsigned char> salt = generateSalt(SALT_SIZE);
    std::vector<unsigned char> iv = generateSalt(IV_SIZE);

    // Derive the encryption key using the generated salt
    std::vector<unsigned char> key = deriveKey(password, salt);

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
    std::vector<unsigned char> salt(SALT_SIZE);
    std::vector<unsigned char> iv(IV_SIZE);
    std::string encryptedText;

    // Base64 decode the encrypted data
    std::string ciphertext = base64Decode(encodedCiphertext);

    if (ciphertext.size() > salt.size() + iv.size()) {
        // Read the salt and IV from the ciphertext
        salt.assign(ciphertext.begin(), ciphertext.begin() + salt.size());
        iv.assign(ciphertext.begin() + salt.size(), ciphertext.begin() + salt.size() + iv.size());

        encryptedText.assign(ciphertext.begin() + salt.size() + iv.size(), ciphertext.end());
    } else {
        throw std::runtime_error("invalid ciphertext.");
    }

    // Derive the decryption key from the password and the salt
    std::vector<unsigned char> key = deriveKey(password, salt);

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
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintextLength, &finalLength) != 1) {
        throw std::runtime_error("Failed to finalize decryption.");
    }
    plaintextLength += finalLength;

    std::string decryptedText(reinterpret_cast<char *>(plaintext.data()), plaintextLength);

    return decryptedText;
}

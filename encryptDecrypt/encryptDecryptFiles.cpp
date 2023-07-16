#include <iostream>
#include <fstream>
#include <memory>
#include <gcrypt.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <sodium/utils.h>
#include "cryptoCipher.hpp"
#include "encryptDecrypt.hpp"

constexpr int MAX_KEY_SIZE = EVP_MAX_KEY_LENGTH;    // For bounds checking
constexpr size_t CHUNK_SIZE = 4096;                 // Read files in chunks of 4kB
constexpr unsigned int PBKDF2_ITERATIONS = 100'000; // Iterations for PBKDF2 key derivation


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
deriveKey(const std::string &password, const std::vector<unsigned char> &salt, const int &keySize) {
    // A validation check
    if (keySize > MAX_KEY_SIZE || keySize < 1)
        throw std::length_error("Invalid Key size.");

    OSSL_PARAM params[6], *p = params;

    // Fetch the PBKDF2 implementation
    EVP_KDF *kdf = EVP_KDF_fetch(libContext, "PBKDF2", propertyQuery);
    if (kdf == nullptr)
        throw std::runtime_error("Failed to fetch PBKDF2 implementation.");

    // Dynamic memory management of kdf
    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdfPtr(kdf, EVP_KDF_free);

    // Create a context for the key derivation operation
    EVP_KDF_CTX *kdfCtx = EVP_KDF_CTX_new(kdf);
    if (kdfCtx == nullptr)
        throw std::runtime_error("Failed to create key derivation context.");

    // Dynamic memory management of kdfCtx
    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> ctxPtr(kdfCtx, EVP_KDF_CTX_free);

    /*************** Set the required parameters **************/
    // Set the password to derive the key from
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *) password.data(), password.size());

    // Set the salt
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *) salt.data(), salt.size());

    // Set the number of iterations
    unsigned int iterations{PBKDF2_ITERATIONS};
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);

    // Use BLAKE2b512 as the hash function for the digest
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) "BLAKE2B512", 0);

    // Enable SP800-132 compliance checks (iterations >= 1000, salt >= 128 bits, key >= 112 bits)
    int pkcs5 = 0;
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, &pkcs5);

    *p = OSSL_PARAM_construct_end(); // Finalize parameter construction
    /************** end of parameters construction *************/

    // Derive the key using the parameters
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
 */
void encryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password) {
    // Open both input and output files & throw errors
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile)
        throw std::runtime_error("Failed to open " + inputFile + " for reading.");

    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile)
        throw std::runtime_error("Failed to open " + outputFile + " for writing.");

    // Initialize the cipher
    CryptoCipher cipher;

    // Create the cipher context
    cipher.setCtx();
    if (cipher.getCtx() == nullptr)
        throw std::runtime_error("Failed to create the cipher context.");

    // Fetch the cipher implementation
    cipher.setCipher(libContext, "AES-256-CBC", propertyQuery);
    if (cipher.getCipher() == nullptr)
        throw std::runtime_error("Failed to fetch AES-256-CBC cipher.");

    // Fetch the sizes of the IV and the key for the cipher
    const int ivSize = EVP_CIPHER_get_iv_length(cipher.getCipher());
    const int keySize = EVP_CIPHER_get_key_length(cipher.getCipher());

    // Generate the salt and the initialization vector (IV)
    std::vector<unsigned char> salt = generateSalt(SALT_SIZE);
    std::vector<unsigned char> iv = generateSalt(ivSize);

    // Derive the encryption key
    std::vector<unsigned char> key = deriveKey(password, salt, keySize);

    // Lock the memory holding the key to avoid swapping it to the disk
    sodium_mlock(key.data(), key.size());

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex2(cipher.getCtx(), cipher.getCipher(), key.data(), iv.data(), nullptr) != 1)
        throw std::runtime_error("Failed to initialize encryption.");

    // The key is no longer needed: unlock the memory and zeroize the key contents
    sodium_munlock(key.data(), key.size());

    // Set automatic padding handling
    EVP_CIPHER_CTX_set_padding(cipher.getCtx(), EVP_PADDING_PKCS7);

    // Write the salt and IV to the output file
    outFile.write(reinterpret_cast<const char *>(salt.data()), static_cast<std::streamsize>(salt.size()));
    outFile.write(reinterpret_cast<const char *>(iv.data()), static_cast<std::streamsize>(iv.size()));

    // Encrypt the file
    std::vector<unsigned char> inBuf(CHUNK_SIZE);
    std::vector<unsigned char> outBuf(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);
    int bytesRead, bytesWritten;

    while (true) {
        // Read data from the file in chunks
        inFile.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));
        bytesRead = static_cast<int>(inFile.gcount());
        if (bytesRead <= 0)
            break;

        // Encrypt the data
        if (EVP_EncryptUpdate(cipher.getCtx(), outBuf.data(), &bytesWritten, inBuf.data(), bytesRead) != 1)
            throw std::runtime_error("Failed to encrypt the data.");

        // Write the ciphertext (the encrypted data) to the output file
        outFile.write(reinterpret_cast<const char *>(outBuf.data()), bytesWritten);
        outFile.flush(); // Ensure data is written immediately
    }

    // Finalize the encryption operation
    if (EVP_EncryptFinal_ex(cipher.getCtx(), outBuf.data(), &bytesWritten) != 1)
        throw std::runtime_error("Failed to finalize encryption.");

    // Write the last chunk
    outFile.write(reinterpret_cast<const char *>(outBuf.data()), bytesWritten);
}

/**
 * @brief decrypts a file encrypted using AES256 in CBC mode.
 * @param inputFile the file to be decrypted.
 * @param outputFile the file to store the decrypted content.
 * @param password the password used to decrypt the file.
 */
void decryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password) {
    // Open both input and output files
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile)
        throw std::runtime_error("Failed to open " + inputFile + " for reading.");

    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile)
        throw std::runtime_error("Failed to open " + outputFile + " for writing.");

    // Initialize the cipher
    CryptoCipher cipher;

    // Initialize the cipher context
    cipher.setCtx();
    if (cipher.getCtx() == nullptr)
        throw std::runtime_error("Failed to create the cipher context.");

    // Fetch the cipher implementation
    cipher.setCipher(libContext, "AES-256-CBC", propertyQuery);
    if (cipher.getCipher() == nullptr)
        throw std::runtime_error("Failed to fetch AES-256-CBC cipher.");

    // Fetch the sizes of the IV and the key for the cipher
    const int ivSize = EVP_CIPHER_get_iv_length(cipher.getCipher());
    const int keySize = EVP_CIPHER_get_key_length(cipher.getCipher());

    std::vector<unsigned char> salt(SALT_SIZE);
    std::vector<unsigned char> iv(ivSize);

    size_t saltBytesRead, ivBytesRead;

    // Read the salt and IV from the input file
    inFile.read(reinterpret_cast<char *>(salt.data()), static_cast<std::streamsize>(salt.size()));
    saltBytesRead = inFile.gcount();

    inFile.read(reinterpret_cast<char *>(iv.data()), static_cast<std::streamsize>(iv.size()));
    ivBytesRead = inFile.gcount();

    // Without valid salt and IV, decryption would fail
    if (saltBytesRead < SALT_SIZE || ivBytesRead < ivSize)
        throw std::length_error("Invalid ciphertext.");

    // Derive the decryption key
    std::vector<unsigned char> key = deriveKey(password, salt, keySize);

    // Lock the memory holding the key to avoid swapping it to the disk
    sodium_mlock(key.data(), key.size());

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex2(cipher.getCtx(), cipher.getCipher(), key.data(), iv.data(), nullptr) != 1)
        throw std::runtime_error("Failed to initialize decryption.");

    // The key is no longer needed: unlock the memory and zeroize the key contents
    sodium_munlock(key.data(), key.size());

    // Set automatic padding handling
    EVP_CIPHER_CTX_set_padding(cipher.getCtx(), EVP_PADDING_PKCS7);

    // Decrypt the file
    std::vector<unsigned char> inBuf(CHUNK_SIZE);
    std::vector<unsigned char> outBuf(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);
    int bytesRead, bytesWritten;

    while (true) {
        // Read the data in chunks
        inFile.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));
        bytesRead = static_cast<int>(inFile.gcount());
        if (bytesRead <= 0)
            break;

        // Decrypt the data
        if (EVP_DecryptUpdate(cipher.getCtx(), outBuf.data(), &bytesWritten, inBuf.data(), bytesRead) != 1)
            throw std::runtime_error("Failed to decrypt the data.");

        // Write the decrypted data to the output file
        outFile.write(reinterpret_cast<const char *>(outBuf.data()), bytesWritten);
        outFile.flush();
    }

    // Finalize the decryption operation
    if (EVP_DecryptFinal_ex(cipher.getCtx(), outBuf.data(), &bytesWritten) != 1)
        throw std::runtime_error("Failed to finalize decryption.");

    outFile.write(reinterpret_cast<const char *>(outBuf.data()), bytesWritten);
    outFile.flush();
}

void
encryptFileHeavy(const std::string &inputFilePath, const std::string &outputFilePath, const std::string &password) {
    // Ensure the files are readable/writable
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    if (!inputFile)
        throw std::runtime_error("Failed to open " + inputFilePath + " for reading.");

    std::ofstream outputFile(outputFilePath, std::ios::binary);
    if (!outputFile)
        throw std::runtime_error("Failed to open " + outputFilePath + " for writing.");

    gcry_error_t err;   // error tracker

    // Set up the encryption context
    gcry_cipher_hd_t cipherHandle;
    err = gcry_cipher_open(&cipherHandle, GCRY_CIPHER_SERPENT256, GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    if (err)
        throw std::runtime_error(std::string(gcry_strsource(err)) + ": " + gcry_strerror(err));

    // Check the key size and the IV size required by the cipher
    size_t ivSize = gcry_cipher_get_algo_blklen(GCRY_CIPHER_SERPENT256);
    size_t keySize = gcry_cipher_get_algo_keylen(GCRY_CIPHER_SERPENT256);

    // Set key size to default (256 bits) if the previous call failed
    if (keySize == 0)
        keySize = KEY_SIZE_256;

    // Generate a random salt and a random IV
    std::vector<unsigned char> salt = generateSalt(SALT_SIZE);
    std::vector<unsigned char> iv = generateSalt(static_cast<int>(ivSize));

    // Derive the key
    std::vector<unsigned char> key = deriveKey(password, salt, static_cast<int>(keySize));

    // Lock the memory holding the key to avoid swapping it to the disk
    sodium_mlock(key.data(), key.size());

    // Set the key
    err = gcry_cipher_setkey(cipherHandle, key.data(), key.size());
    if (err)
        throw std::runtime_error("Failed to set the encryption key: " + std::string(gcry_strerror(err)));
    // TODO: Unlock the key at an appropriate time

    // Set the IV in the encryption context
    err = gcry_cipher_setiv(cipherHandle, iv.data(), iv.size());
    if (err)
        throw std::runtime_error("encryption set iv: " + std::string(gcry_strsource(err)) + ": " + gcry_strerror(err));

    // Write the salt and the IV to the output file
    outputFile.write(reinterpret_cast<const char *>(salt.data()), static_cast<std::streamsize>(salt.size()));
    outputFile.write(reinterpret_cast<const char *>(iv.data()), static_cast<std::streamsize>(iv.size()));

    // Encrypt the file in chunks
    std::vector<unsigned char> buffer(CHUNK_SIZE);
    while (!inputFile.eof()) {
        inputFile.read(reinterpret_cast<char *>(buffer.data()), CHUNK_SIZE);
        const auto bytesRead = inputFile.gcount();

        // Encrypt the chunk
        err = gcry_cipher_encrypt(cipherHandle, buffer.data(), buffer.size(), nullptr, 0);
        if (err)
            throw std::runtime_error("Failed to encrypt file: " + std::string(gcry_strerror(err)));

        // Write the encrypted chunk to the output file
        outputFile.write(reinterpret_cast<const char *>(buffer.data()), bytesRead);
    }

    // Clean up
    gcry_cipher_close(cipherHandle);
}

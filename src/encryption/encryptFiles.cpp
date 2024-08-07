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

#include <iostream>
#include <fstream>
#include <memory>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <sodium.h>
#include <format>
#include <mutex>
#include <vector>
#include <gcrypt.h>

import cryptoCipher;
import secureAllocator;
import mimallocSTL;

module encryption;

constexpr int MAX_KEY_SIZE = EVP_MAX_KEY_LENGTH;    ///< Maximum length of a key
constexpr std::streamsize CHUNK_SIZE = 4096;        ///< Read/Write files in chunks of 4 kB
constexpr unsigned int PBKDF2_ITERATIONS = 100'000; ///< Iterations for PBKDF2 key derivation


/// \brief Generates random bytes using a CSPRNG.
/// \param saltSize number of bytes of salt to generate.
/// \return the generated salt as a vector.
privacy::vector<unsigned char> generateSalt(const int saltSize) {
    std::mutex m;
    privacy::vector<unsigned char> salt(saltSize);

    if (std::scoped_lock lock(m); RAND_bytes(salt.data(), saltSize) != 1) {
        std::cerr << "Failed to seed OpenSSL's CSPRNG properly."
                "\nPlease check your system's randomness utilities." << std::endl;

        randombytes_buf(salt.data(), salt.size()); // Use Sodium's random generator as a backup
    }
    return salt;
}

/// \brief Derives a key from a password and a salt.
/// \param password the password.
/// \param salt the salt.
/// \param keySize the size (length) of the key in bytes.
/// \return the generated key.
///
/// \throws std::length_error if the key size is invalid.
/// \throws std::runtime_error if the key derivation fails or if the PBKDF2 implementation is not available.
///
/// \details Key derivation is done using the PBKDF2 algorithm.
/// \details BLAKE2b512 is used as the hash function for PBKDF2
/// and the number of iterations is set to 100,000.
privacy::vector<unsigned char>
deriveKey(const privacy::string &password, const privacy::vector<unsigned char> &salt, const int &keySize) {
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

    /// ************* Set the required parameters *************
    // Set the password to derive the key from
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, const_cast<char *>(password.data()),
                                             password.size());

    // Set the salt
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<unsigned char *>(salt.data()),
                                             salt.size());

    // Set the number of iterations
    unsigned int iterations{PBKDF2_ITERATIONS};
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);

    // Use BLAKE2b512 as the hash function for the digest
    char hashFn[] = "BLAKE2B512";
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, hashFn, 0);

    // Enable SP800-132 compliance checks (iterations >= 1000, salt >= 128 bits, key >= 112 bits)
    int pkcs5 = 0;
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, &pkcs5);

    *p = OSSL_PARAM_construct_end(); // Finalize parameter construction
    /// ************ end of parameters construction ************

    // Derive the key using the parameters
    privacy::vector<unsigned char> key(keySize);
    if (EVP_KDF_derive(kdfCtx, key.data(), keySize, params) != 1)
        throw std::runtime_error("Failed to derive key.");

    return key;
}

/// \brief Encrypts a file with a strong block cipher.
/// \param inputFile The file to be encrypted.
/// \param outputFile The file to store the encrypted content.
/// \param password The password used to encrypt the file.
/// \param algo The cipher algorithm to use.
///
/// \throws std::runtime_error if the encryption fails, and for other (documented) errors.
///
/// \details Available ciphers: AES-256, Camellia-256, and Aria-256.
/// \details Encryption mode: CBC.
/// \details Key derivation function: PBKDF2 with BLAKE2b512 as the digest function (salted).
/// \details The IV is generated randomly with a CSPRNG and prepended to the encrypted file.
void encryptFile(const miSTL::string &inputFile, const miSTL::string &outputFile, const privacy::string &password,
                 const miSTL::string &algo) {
    // Open the input file for reading
    std::ifstream inFile(inputFile.c_str(), std::ios::binary);
    if (!inFile)
        throw std::runtime_error(std::format("Failed to open '{}' for reading.", inputFile));

    // Open the output file for writing
    std::ofstream outFile(outputFile.c_str(), std::ios::binary | std::ios::trunc);
    if (!outFile)
        throw std::runtime_error(std::format("Failed to open '{}' for writing.", outputFile));

    // Initialize the cipher
    CryptoCipher cipher;

    // Create the cipher context
    cipher.setCtx();
    if (cipher.getCtx() == nullptr)
        throw std::runtime_error("Failed to create the cipher context.");

    // Fetch the cipher implementation
    cipher.setCipher(libContext, algo.c_str(), propertyQuery);
    if (cipher.getCipher() == nullptr)
        throw std::runtime_error(std::format("Failed to fetch {} cipher.", algo));

    // Fetch the sizes of the IV and the key for the cipher
    const int ivSize = EVP_CIPHER_get_iv_length(cipher.getCipher());
    const int keySize = EVP_CIPHER_get_key_length(cipher.getCipher());

    // Generate the salt, and the initialization vector (IV)
    privacy::vector<unsigned char> salt = generateSalt(SALT_SIZE);
    privacy::vector<unsigned char> iv = generateSalt(ivSize);

    // Derive the encryption key
    privacy::vector<unsigned char> key = deriveKey(password, salt, keySize);

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex2(cipher.getCtx(), cipher.getCipher(), key.data(), iv.data(), nullptr) != 1)
        throw std::runtime_error("Failed to initialize encryption.");

    // The key is no longer needed: zeroize its contents
    sodium_memzero(key.data(), key.size());

    // Set automatic padding handling
    EVP_CIPHER_CTX_set_padding(cipher.getCtx(), EVP_PADDING_PKCS7);

    // Write the salt and IV to the output file
    outFile.write(reinterpret_cast<const char *>(salt.data()), static_cast<std::streamsize>(salt.size()));
    outFile.write(reinterpret_cast<const char *>(iv.data()), static_cast<std::streamsize>(iv.size()));

    // Buffers for file processing
    unsigned char inBuf[CHUNK_SIZE];
    unsigned char outBuf[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];

    // Lock the buffers
    sodium_mlock(inBuf, CHUNK_SIZE);
    sodium_mlock(outBuf, CHUNK_SIZE);

    int bytesRead, bytesWritten;
    // The encryption loop
    while (!inFile.eof()) {
        // Read data from the file in chunks
        inFile.read(reinterpret_cast<char *>(inBuf), CHUNK_SIZE);
        bytesRead = static_cast<int>(inFile.gcount());

        // Encrypt the chunk
        if (EVP_EncryptUpdate(cipher.getCtx(), outBuf, &bytesWritten, inBuf, bytesRead) != 1)
            throw std::runtime_error("Failed to encrypt the data.");

        // Write the ciphertext (the encrypted data) to the output file
        outFile.write(reinterpret_cast<const char *>(outBuf), bytesWritten);
        // outFile.flush(); // Ensure data is written immediately
    }

    // Finalize the encryption operation
    if (EVP_EncryptFinal_ex(cipher.getCtx(), outBuf, &bytesWritten) != 1)
        throw std::runtime_error("Failed to finalize encryption.");

    // Write the last chunk
    outFile.write(reinterpret_cast<const char *>(outBuf), bytesWritten);

    // Unlock and zeroize the buffers
    sodium_munlock(inBuf, CHUNK_SIZE);
    sodium_munlock(outBuf, CHUNK_SIZE);
}

/// \brief Decrypts a file encrypted by encryptFile() function.
/// \param inputFile The file to be decrypted.
/// \param outputFile The file to store the decrypted content.
/// \param password The password used to decrypt the file.
/// \param algo The cipher algorithm used to encrypt the file.
///
/// \throws std::runtime_error if the decryption fails, and for other (documented) errors.
void decryptFile(const miSTL::string &inputFile, const miSTL::string &outputFile, const privacy::string &password,
                 const miSTL::string &algo) {
    // Open the input file for reading
    std::ifstream inFile(inputFile.c_str(), std::ios::binary);
    if (!inFile)
        throw std::runtime_error(std::format("Failed to open '{}' for reading.", inputFile));

    // Open the output file for writing
    std::ofstream outFile(outputFile.c_str(), std::ios::binary | std::ios::trunc);
    if (!outFile)
        throw std::runtime_error(std::format("Failed to open '{}' for writing.", outputFile));

    // Initialize the cipher
    CryptoCipher cipher;

    // Initialize the cipher context
    cipher.setCtx();
    if (cipher.getCtx() == nullptr)
        throw std::runtime_error("Failed to create the cipher context.");

    // Fetch the cipher implementation
    cipher.setCipher(libContext, algo.c_str(), propertyQuery);
    if (cipher.getCipher() == nullptr)
        throw std::runtime_error(std::format("Failed to fetch {} cipher.", algo));

    // Fetch the sizes of the IV and the key for the cipher
    const int ivSize = EVP_CIPHER_get_iv_length(cipher.getCipher());
    const int keySize = EVP_CIPHER_get_key_length(cipher.getCipher());

    privacy::vector<unsigned char> salt(SALT_SIZE);
    privacy::vector<unsigned char> iv(ivSize);

    std::size_t saltBytesRead, ivBytesRead;

    // Read the salt and IV from the input file
    inFile.read(reinterpret_cast<char *>(salt.data()), static_cast<std::streamsize>(salt.size()));
    saltBytesRead = inFile.gcount();

    inFile.read(reinterpret_cast<char *>(iv.data()), static_cast<std::streamsize>(iv.size()));
    ivBytesRead = inFile.gcount();

    // Without valid salt and IV, decryption would fail
    if (saltBytesRead < SALT_SIZE || ivBytesRead < static_cast<std::size_t>(ivSize))
        throw std::length_error("Invalid ciphertext.");

    // Derive the decryption key
    privacy::vector<unsigned char> key = deriveKey(password, salt, keySize);

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex2(cipher.getCtx(), cipher.getCipher(), key.data(), iv.data(), nullptr) != 1)
        throw std::runtime_error("Failed to initialize decryption.");

    // The key is no longer needed, zeroize the key contents
    sodium_memzero(key.data(), key.size());

    // Set automatic padding handling
    EVP_CIPHER_CTX_set_padding(cipher.getCtx(), EVP_PADDING_PKCS7);

    // Buffers for file processing
    unsigned char inBuf[CHUNK_SIZE];
    unsigned char outBuf[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];

    // Lock the buffers
    sodium_mlock(inBuf, CHUNK_SIZE);
    sodium_mlock(outBuf, CHUNK_SIZE);
    int bytesRead, bytesWritten;

    while (!inFile.eof()) {
        // Read the data in chunks
        inFile.read(reinterpret_cast<char *>(inBuf), CHUNK_SIZE);
        bytesRead = static_cast<int>(inFile.gcount());

        // Decrypt the chunk
        if (EVP_DecryptUpdate(cipher.getCtx(), outBuf, &bytesWritten, inBuf, bytesRead) != 1)
            throw std::runtime_error("Failed to decrypt the data.");

        // Write the decrypted data to the output file
        outFile.write(reinterpret_cast<const char *>(outBuf), bytesWritten);
        // outFile.flush();
    }

    // Finalize the decryption operation
    if (EVP_DecryptFinal_ex(cipher.getCtx(), outBuf, &bytesWritten) != 1)
        throw std::runtime_error("Failed to finalize decryption.");

    outFile.write(reinterpret_cast<const char *>(outBuf), bytesWritten);

    // Unlock and zeroize the buffers
    sodium_munlock(inBuf, CHUNK_SIZE);
    sodium_munlock(outBuf, CHUNK_SIZE);
}

/// \brief Throws a thread-safe Gcrypt error.
/// \param err Gcrypt error value.
/// \param message the error message.
/// \throws std::runtime_error with the error message.
inline void throwSafeError(const gcry_error_t &err, const std::string_view message) {
    std::mutex m;
    std::scoped_lock<std::mutex> locker(m);
    throw std::runtime_error(std::format("{}: {}", message, gcry_strerror(err)));
}

/// \brief Encrypts a file with ciphers that use more rounds.
/// \param inputFilePath the file to be encrypted.
/// \param outputFilePath the file to save the ciphertext to.
/// \param password the password used to encrypt the file.
/// \param algorithm the cipher algorithm to use.
///
/// \throws std::runtime_error if the encryption fails, and for other (documented) errors.
///
/// \details Available ciphers: Serpent-256 and Twofish-256.
/// \details Encryption mode: Counter (CTR).
/// \details The key is derived from the password and a randomly generated salt
/// using PBKDF2 with BLAKE2b-512 as the hash function.
/// \details The IV(nonce) is randomly generated and stored in the output file.
void
encryptFileWithMoreRounds(const miSTL::string &inputFilePath, const miSTL::string &outputFilePath,
                          const privacy::string &password, const gcry_cipher_algos &algorithm) {
    // Open the input file for reading
    std::ifstream inputFile(inputFilePath.c_str(), std::ios::binary);
    if (!inputFile)
        throw std::runtime_error(std::format("Failed to open '{}' for reading.", inputFilePath));

    // Open the output file for writing
    std::ofstream outputFile(outputFilePath.c_str(), std::ios::binary | std::ios::trunc);
    if (!outputFile)
        throw std::runtime_error(std::format("Failed to open '{}' for writing.", outputFilePath));

    gcry_error_t err; // error tracker

    // Set up the encryption context
    gcry_cipher_hd_t cipherHandle;
    err = gcry_cipher_open(&cipherHandle, algorithm, GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    if (err)
        throwSafeError(err, "Failed to create the encryption cipher context");

    // Check the key size, and the counter-size required by the cipher
    std::size_t ctrSize = gcry_cipher_get_algo_blklen(algorithm);
    std::size_t keySize = gcry_cipher_get_algo_keylen(algorithm);

    // Default the key size to 256 bits if the previous call failed
    if (keySize == 0) keySize = KEY_SIZE_256;
    if (ctrSize == 0) ctrSize = 16; // Default the counter size to 128 bits if we can't get the block length

    // Generate a random salt, and a random counter
    privacy::vector<unsigned char> salt = generateSalt(SALT_SIZE);
    privacy::vector<unsigned char> ctr = generateSalt(static_cast<int>(ctrSize));

    // Derive the key
    privacy::vector<unsigned char> key = deriveKey(password, salt, static_cast<int>(keySize));

    // Set the key
    err = gcry_cipher_setkey(cipherHandle, key.data(), key.size());
    if (err)
        throwSafeError(err, "Failed to set the encryption key");

    // Zeroize the key, we don't need it anymore
    sodium_memzero(key.data(), key.size());

    // Set the counter
    err = gcry_cipher_setctr(cipherHandle, ctr.data(), ctr.size());
    if (err)
        throwSafeError(err, "Failed to set the encryption counter");

    // Write the salt, and the counter to the output file
    outputFile.write(reinterpret_cast<const char *>(salt.data()), static_cast<std::streamsize>(salt.size()));
    outputFile.write(reinterpret_cast<const char *>(ctr.data()), static_cast<std::streamsize>(ctr.size()));

    unsigned char buffer[CHUNK_SIZE];
    // Lock the buffer
    sodium_mlock(buffer, CHUNK_SIZE);

    // Encrypt the file in chunks
    while (!inputFile.eof()) {
        inputFile.read(reinterpret_cast<char *>(buffer), CHUNK_SIZE);
        const auto bytesRead = inputFile.gcount();

        // Encrypt the chunk
        err = gcry_cipher_encrypt(cipherHandle, buffer, CHUNK_SIZE, nullptr, 0);
        if (err)
            throwSafeError(err, "Failed to encrypt file");

        // Write the encrypted chunk to the output file
        outputFile.write(reinterpret_cast<const char *>(buffer), bytesRead);
    }
    // Release the handle
    gcry_cipher_close(cipherHandle);
    // Unlock the buffer
    sodium_munlock(buffer, CHUNK_SIZE);
}

/// \brief Decrypts a file encrypted by encryptFileWithMoreRounds() function.
/// \param inputFilePath The file to be decrypted.
/// \param outputFilePath The file to store the decrypted content.
/// \param password The password used to decrypt the file.
/// \param algorithm The cipher algorithm used to encrypt the file.
///
/// \throws std::runtime_error if the decryption fails, and for other (documented) errors.
void
decryptFileWithMoreRounds(const miSTL::string &inputFilePath, const miSTL::string &outputFilePath,
                          const privacy::string &password, const gcry_cipher_algos &algorithm) {
    // Open the input file for reading
    std::ifstream inputFile(inputFilePath.c_str(), std::ios::binary);
    if (!inputFile)
        throw std::runtime_error(std::format("Failed to open '{}' for reading.", inputFilePath));

    // Open the output file for writing
    std::ofstream outputFile(outputFilePath.c_str(), std::ios::binary | std::ios::trunc);
    if (!outputFile)
        throw std::runtime_error(std::format("Failed to open '{}' for writing.", outputFilePath));

    // Fetch the cipher's counter-size and key size
    std::size_t ctrSize = gcry_cipher_get_algo_blklen(algorithm);
    std::size_t keySize = gcry_cipher_get_algo_keylen(algorithm);

    if (keySize == 0) keySize = KEY_SIZE_256;
    if (ctrSize == 0) ctrSize = 16;

    privacy::vector<unsigned char> salt(SALT_SIZE);
    privacy::vector<unsigned char> ctr(ctrSize);
    std::size_t saltBytesRead, ctrBytesRead;

    // Read the salt, and the counter from the input file
    inputFile.read(reinterpret_cast<char *>(salt.data()), static_cast<std::streamsize>(salt.size()));
    saltBytesRead = inputFile.gcount();

    inputFile.read(reinterpret_cast<char *>(ctr.data()), static_cast<std::streamsize>(ctr.size()));
    ctrBytesRead = inputFile.gcount();

    // Without valid salt and counter, decryption would fail, or the plaintext would be garbage
    if (saltBytesRead < SALT_SIZE or ctrBytesRead < ctrSize)
        throw std::length_error("Invalid ciphertext.");

    // Derive the key
    privacy::vector<unsigned char> key = deriveKey(password, salt, static_cast<int>(keySize));

    // Set up the decryption context
    gcry_error_t err;
    gcry_cipher_hd_t cipherHandle;
    err = gcry_cipher_open(&cipherHandle, algorithm, GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    if (err)
        throwSafeError(err, "Failed to create the decryption cipher context");

    // Set the decryption key
    err = gcry_cipher_setkey(cipherHandle, key.data(), key.size());
    if (err)
        throwSafeError(err, "Failed to set the decryption key");

    // Key is not needed anymore, zeroize it
    sodium_memzero(key.data(), key.size());

    // Set the counter
    err = gcry_cipher_setctr(cipherHandle, ctr.data(), ctr.size());
    if (err)
        throwSafeError(err, "Failed to set the decryption counter");

    unsigned char buffer[CHUNK_SIZE];
    // Lock the buffer
    sodium_mlock(buffer, CHUNK_SIZE);

    // Decrypt the file in chunks
    while (!inputFile.eof()) {
        inputFile.read(reinterpret_cast<char *>(buffer), CHUNK_SIZE);
        const auto bytesRead = inputFile.gcount();

        // Decrypt the chunk in place
        err = gcry_cipher_decrypt(cipherHandle, buffer, CHUNK_SIZE, nullptr, 0);
        if (err)
            throwSafeError(err, "Failed to decrypt the ciphertext");

        // Write the decrypted chunk to the output file
        outputFile.write(reinterpret_cast<const char *>(buffer), bytesRead);
    }
    // Release resources
    gcry_cipher_close(cipherHandle);
    // Unlock the buffer
    sodium_munlock(buffer, CHUNK_SIZE);
}

// Privacy Shield: A Suite of Tools Designed to Facilitate Privacy Management.
// Copyright (C) 2023  Ian Duncan <dr8co@duck.com>
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

#include <iostream>
#include <mutex>
#include <sodium.h>
#include <format>
#include "encryptDecrypt.hpp"
#include "cryptoCipher.hpp"
#include "../utils/utils.hpp"

/**
 * @brief Encrypts a string using symmetric unauthenticated encryption.
 * @param plaintext The string to be encrypted.
 * @param password The string to be used to derive the encryption key.
 * @return Base64-encoded ciphertext (the encrypted data).
 *
 * @details Available ciphers: AES-256, Camellia-256, and Aria-256.
 * @details Encryption mode: CBC.
 * @details The key is derived from the password using PBKDF2 with 100,000 rounds (salted).
 * @details The IV is generated randomly using a CSPRNG and prepended to the ciphertext.
 */
privacy::string
encryptString(const privacy::string &plaintext, const privacy::string &password, const std::string &algo) {
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

    // Derive the encryption key using the generated salt
    privacy::vector<unsigned char> key = deriveKey(password, salt, keySize);

    int block_size = EVP_CIPHER_get_block_size(cipher.getCipher());
    privacy::vector<unsigned char> ciphertext(plaintext.size() + block_size);
    int ciphertextLength = 0;

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex2(cipher.getCtx(), cipher.getCipher(), key.data(), iv.data(), nullptr) != 1)
        throw std::runtime_error("Failed to initialize encryption.");

    // The key is no longer needed: zeroize its contents
    sodium_memzero(key.data(), key.size());

    // Encrypt the plaintext into the ciphertext
    if (EVP_EncryptUpdate(cipher.getCtx(), ciphertext.data(), &ciphertextLength,
                          reinterpret_cast<const unsigned char *>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("Failed to encrypt the data.");
    }
    // Finalize the encryption operation
    int finalLength = 0;
    if (EVP_EncryptFinal_ex(cipher.getCtx(), ciphertext.data() + ciphertextLength, &finalLength) != 1)
        throw std::runtime_error("Failed to finalize encryption.");

    ciphertextLength += finalLength;
    ciphertext.resize(ciphertextLength); // Important!

    // Export the salt, iv, and the ciphertext
    privacy::vector<unsigned char> result;
    result.reserve(salt.size() + iv.size() + ciphertext.size()); // pre-allocate memory to improve performance

    // Construct result = salt + iv + ciphertext in that order
    result.assign(salt.begin(), salt.end());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    // Return Base64-encoded ciphertext
    return privacy::string{base64Encode(result)};
}

/**
 * @brief Decrypts a string encrypted with the encryptString() function.
 * @param encodedCiphertext Base64-encoded ciphertext to be decrypted.
 * @param password The string to be used to derive the decryption key.
 * @return The decrypted string (the plaintext).
 */
privacy::string
decryptString(const std::string &encodedCiphertext, const privacy::string &password, const std::string &algo) {
    CryptoCipher cipher;

    // Create the cipher context
    cipher.setCtx();
    if (cipher.getCtx() == nullptr)
        throw std::runtime_error("Failed to create the cipher context.");

    // Fetch the cipher implementation
    cipher.setCipher(libContext, algo.c_str(), propertyQuery);
    if (cipher.getCipher() == nullptr)
        throw std::runtime_error(std::format("Failed to fetch {} cipher.", algo));

    // Fetch the sizes of IV and the key from the cipher
    const int ivSize = EVP_CIPHER_get_iv_length(cipher.getCipher());
    const int keySize = EVP_CIPHER_get_key_length(cipher.getCipher());

    privacy::vector<unsigned char> salt(SALT_SIZE);
    privacy::vector<unsigned char> iv(ivSize);
    privacy::vector<unsigned char> encryptedText;

    // Base64 decode the encoded ciphertext
    std::vector<unsigned char> ciphertext = base64Decode(encodedCiphertext);

    if (ciphertext.size() > (static_cast<std::size_t>(SALT_SIZE) + ivSize)) [[likely]] {
        // Read the salt and IV from the ciphertext
        salt.assign(ciphertext.begin(), ciphertext.begin() + SALT_SIZE);
        iv.assign(ciphertext.begin() + SALT_SIZE, ciphertext.begin() + SALT_SIZE + ivSize);

        encryptedText.assign(ciphertext.begin() + static_cast<long>(salt.size() + iv.size()), ciphertext.end());
    } else
        throw std::runtime_error("invalid ciphertext.");

    // Derive the decryption key from the password, and the salt
    privacy::vector<unsigned char> key = deriveKey(password, salt, keySize);

    int block_size = EVP_CIPHER_get_block_size(cipher.getCipher());
    privacy::vector<unsigned char> plaintext(encryptedText.size() + block_size);
    int plaintextLength = 0;

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex2(cipher.getCtx(), cipher.getCipher(), key.data(), iv.data(), nullptr) != 1)
        throw std::runtime_error("Failed to initialize decryption.");

    // The key is no longer needed: zeroize it
    sodium_memzero(key.data(), key.size());

    // Decrypt the ciphertext into the plaintext
    if (EVP_DecryptUpdate(cipher.getCtx(), plaintext.data(), &plaintextLength,
                          encryptedText.data(),
                          static_cast<int>(encryptedText.size())) != 1) {
        throw std::runtime_error("Failed to decrypt the data.");
    }

    // Finalize the decryption operation
    int finalLength = 0;
    if (EVP_DecryptFinal_ex(cipher.getCtx(), plaintext.data() + plaintextLength, &finalLength) != 1)
        throw std::runtime_error("Failed to finalize decryption.");

    plaintextLength += finalLength;

    privacy::string decryptedText(reinterpret_cast<char *>(plaintext.data()), plaintextLength);

    return decryptedText;
}

inline void throwSafeError(gcry_error_t &err, const std::string &message) {
    std::mutex m;
    std::scoped_lock<std::mutex> locker(m);
    throw std::runtime_error(std::format("{}: {}", message, gcry_strerror(err)));
}

/**
 * @brief Encrypts a string with ciphers with more rounds.
 * @param plaintext The string to be encrypted.
 * @param password The string to be used to derive the encryption key.
 * @return Base64-encoded ciphertext (the encrypted data).
 *
 * @details Available ciphers: Serpent-256 and Twofish-256.
 * @details Encryption mode: CTR.
 * @details Key derivation function: PBKDF2 with 100,000 rounds.
 * @details The IV(nonce) is generated randomly and prepended to the ciphertext.
 */
privacy::string
encryptStringWithMoreRounds(const privacy::string &plaintext, const privacy::string &password,
                            const gcry_cipher_algos &algorithm) {
    gcry_error_t err;   // error tracker

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
    if (ctrSize == 0) ctrSize = 16;  // Default the counter size to 128 bits if we can't get the block length

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

    // Encrypt the plaintext
    privacy::vector<unsigned char> ciphertext(plaintext.size());
    err = gcry_cipher_encrypt(cipherHandle, ciphertext.data(), ciphertext.size(), plaintext.data(), plaintext.size());
    if (err)
        throwSafeError(err, "Failed to encrypt data");

    // Clean up the resources associated with the encryption handle
    gcry_cipher_close(cipherHandle);

    // Export the salt, ctr, and the ciphertext
    privacy::vector<unsigned char> result;
    result.reserve(salt.size() + ctr.size() + ciphertext.size());

    // Construct result = salt + ctr + ciphertext in that order
    result.assign(salt.begin(), salt.end());
    result.insert(result.end(), ctr.begin(), ctr.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    // Return Base64-encoded ciphertext
    return privacy::string{base64Encode(result)};
}

/**
 * @brief Decrypts a string encrypted by encryptStringWithMoreRounds() function.
 * @param encodedCiphertext Base64-encoded ciphertext to be decrypted.
 * @param password The string to be used to derive the decryption key.
 * @return The decrypted string (the plaintext).
 */
privacy::string
decryptStringWithMoreRounds(const std::string &encodedCiphertext, const privacy::string &password,
                            const gcry_cipher_algos &algorithm) {
    // Fetch the cipher's counter-size and key size
    std::size_t ctrSize = gcry_cipher_get_algo_blklen(algorithm);
    std::size_t keySize = gcry_cipher_get_algo_keylen(algorithm);

    // Default the key size to 256 bits if the previous call failed
    if (keySize == 0) keySize = KEY_SIZE_256;
    if (ctrSize == 0) ctrSize = 16;  // Default the counter size to 128 bits if we can't get the block length

    privacy::vector<unsigned char> salt(SALT_SIZE);
    privacy::vector<unsigned char> ctr(ctrSize);
    privacy::vector<unsigned char> encryptedText;

    // Base64-decode the encoded ciphertext
    std::vector<unsigned char> ciphertext = base64Decode(encodedCiphertext);

    if (ciphertext.size() >= SALT_SIZE + ctrSize) [[likely]] {
        // Read the salt and the counter from the ciphertext
        salt.assign(ciphertext.begin(), ciphertext.begin() + SALT_SIZE);
        ctr.assign(ciphertext.begin() + SALT_SIZE, ciphertext.begin() + SALT_SIZE + static_cast<long>(ctrSize));

        encryptedText.assign(ciphertext.begin() + static_cast<long>(salt.size() + ctr.size()), ciphertext.end());
    } else
        throw std::runtime_error("Invalid ciphertext.");

    std::size_t encryptedTextSize = encryptedText.size();

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

    // Set the counter in the decryption context
    err = gcry_cipher_setctr(cipherHandle, ctr.data(), ctr.size());
    if (err)
        throwSafeError(err, "Failed to set the decryption counter");

    // Decrypt the ciphertext
    privacy::vector<unsigned char> plaintext(encryptedTextSize);
    err = gcry_cipher_decrypt(cipherHandle, plaintext.data(), plaintext.size(), encryptedText.data(),
                              encryptedTextSize);
    if (err)
        throwSafeError(err, "Failed to decrypt the ciphertext");

    // Release the decryption handle's resources
    gcry_cipher_close(cipherHandle);

    // Return the plaintext
    return plaintext.empty() ? "" : privacy::string(reinterpret_cast<char *>(plaintext.data()), encryptedTextSize);
}

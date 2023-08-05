#include <iostream>
#include <openssl/evp.h>
#include <gcrypt.h>
#include <sodium.h>
#include <string>
#include <format>
#include "encryptDecrypt.hpp"
#include "cryptoCipher.hpp"
#include "../utils/utils.hpp"

/**
 * @brief Encrypts a string using AES256 cipher in CBC mode.
 * @param plaintext the string to be encrypted.
 * @param password the string to be used to derive the encryption key.
 * @return Base64-encoded ciphertext (the encrypted data)
 */
std::string encryptString(const std::string &plaintext, const std::string &password) {
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

    // Generate the salt, and the initialization vector (IV)
    std::vector<unsigned char> salt = generateSalt(SALT_SIZE);
    std::vector<unsigned char> iv = generateSalt(ivSize);

    // Derive the encryption key using the generated salt
    std::vector<unsigned char> key = deriveKey(password, salt, keySize);

    // Secure the key from being swapped to the disk
    sodium_mlock(key.data(), key.size());

    int block_size = EVP_CIPHER_get_block_size(cipher.getCipher());
    std::vector<unsigned char> ciphertext(plaintext.size() + block_size);
    int ciphertextLength = 0;

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex2(cipher.getCtx(), cipher.getCipher(), key.data(), iv.data(), nullptr) != 1)
        throw std::runtime_error("Failed to initialize encryption.");

    // The key is no longer needed: unlock its memory and zeroize the contents
    sodium_munlock(key.data(), key.size());

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
    std::vector<unsigned char> result;
    result.reserve(salt.size() + iv.size() + ciphertext.size()); // pre-allocate memory to improve performance

    // Construct result = salt + iv + ciphertext in that order
    result.assign(salt.begin(), salt.end());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    // Return Base64-encoded ciphertext
    return base64Encode(result);
}

/**
 * @brief Decrypts a string using AES256 cipher in CBC mode.
 * @param encodedCiphertext Base64-encoded ciphertext to be decrypted.
 * @param password the string to be used to derive the decryption key.
 * @return the decrypted string (the plaintext)
 */
std::string decryptString(const std::string &encodedCiphertext, const std::string &password) {
    CryptoCipher cipher;

    // Create the cipher context
    cipher.setCtx();
    if (cipher.getCtx() == nullptr)
        throw std::runtime_error("Failed to create the cipher context.");

    // Fetch the cipher implementation
    cipher.setCipher(libContext, "AES-256-CBC", propertyQuery);
    if (cipher.getCipher() == nullptr)
        throw std::runtime_error("Failed to fetch AES-256-CBC cipher.");

    // Fetch the sizes of IV and the key from the cipher
    const int ivSize = EVP_CIPHER_get_iv_length(cipher.getCipher());
    const int keySize = EVP_CIPHER_get_key_length(cipher.getCipher());

    std::vector<unsigned char> salt(SALT_SIZE);
    std::vector<unsigned char> iv(ivSize);
    std::vector<unsigned char> encryptedText;

    // Base64 decode the encoded ciphertext
    std::vector<unsigned char> ciphertext = base64Decode(encodedCiphertext);

    if (ciphertext.size() > (static_cast<size_t>(SALT_SIZE) + ivSize)) [[likely]] {
        // Read the salt and IV from the ciphertext
        salt.assign(ciphertext.begin(), ciphertext.begin() + SALT_SIZE);
        iv.assign(ciphertext.begin() + SALT_SIZE, ciphertext.begin() + SALT_SIZE + ivSize);

        encryptedText.assign(ciphertext.begin() + static_cast<long>(salt.size() + iv.size()), ciphertext.end());
    } else
        throw std::runtime_error("invalid ciphertext.");

    // Derive the decryption key from the password, and the salt
    std::vector<unsigned char> key = deriveKey(password, salt, keySize);

    // Secure the key from being swapped to the disk
    sodium_mlock(key.data(), key.size());

    int block_size = EVP_CIPHER_get_block_size(cipher.getCipher());
    std::vector<unsigned char> plaintext(encryptedText.size() + block_size);
    int plaintextLength = 0;

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex2(cipher.getCtx(), cipher.getCipher(), key.data(), iv.data(), nullptr) != 1)
        throw std::runtime_error("Failed to initialize decryption.");

    // The key is no longer needed: unlock its memory and zeroize the contents
    sodium_munlock(key.data(), key.size());

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

    std::string decryptedText(reinterpret_cast<char *>(plaintext.data()), plaintextLength);

    return decryptedText;
}

/**
 * @brief Encrypts a string using 256-bit Serpent block cipher in CTR mode.
 * @param plaintext the string to be encrypted.
 * @param password the string to be used to derive the encryption key.
 * @return Base64-encoded ciphertext (the encrypted data)
 */
std::string
encryptStringHeavy(const std::string &plaintext, const std::string &password) {
    gcry_error_t err;   // error tracker
    auto algorithm = GCRY_CIPHER_SERPENT256;

    // Set up the encryption context
    gcry_cipher_hd_t cipherHandle;
    err = gcry_cipher_open(&cipherHandle, algorithm, GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    if (err)
        throw std::runtime_error(std::format("{}: {}", gcry_strsource(err), gcry_strerror(err)));

    // Check the key size, and the IV size required by the cipher
    size_t ivSize = gcry_cipher_get_algo_blklen(algorithm);
    size_t keySize = gcry_cipher_get_algo_keylen(algorithm);

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
        throw std::runtime_error(std::format("Failed to set the encryption key: {}", gcry_strerror(err)));

    // Zeroize the key, we don't need it anymore
    sodium_munlock(key.data(), key.size());

    // Set the IV in the encryption context
    err = gcry_cipher_setiv(cipherHandle, iv.data(), iv.size());
    if (err)
        throw std::runtime_error(
                std::format("Failed to set the encryption IV: {}: {}", gcry_strsource(err), gcry_strerror(err)));

    // Encrypt the plaintext
    std::vector<unsigned char> ciphertext(plaintext.size());
    err = gcry_cipher_encrypt(cipherHandle, ciphertext.data(), ciphertext.size(), plaintext.data(), plaintext.size());
    if (err)
        throw std::runtime_error(std::format("Failed to encrypt data: {}", gcry_strerror(err)));

    // Clean up the resources associated with the encryption handle
    gcry_cipher_close(cipherHandle);

    // Export the salt, iv, and the ciphertext
    std::vector<unsigned char> result;
    result.reserve(salt.size() + iv.size() + ciphertext.size());

    // Construct result = salt + iv + ciphertext in that order
    result.assign(salt.begin(), salt.end());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    // Return Base64-encoded ciphertext
    return base64Encode(result);
}

/**
 * @brief Decrypts a string using the 256-bit Serpent block cipher in CBC mode.
 * @param encodedCiphertext Base64-encoded ciphertext to be decrypted.
 * @param password the string to be used to derive the decryption key.
 * @return the decrypted string (the plaintext)
 */
std::string
decryptStringHeavy(const std::string &encodedCiphertext, const std::string &password) {
    // Fetch the cipher's IV size and key size
    auto algorithm = GCRY_CIPHER_SERPENT256;

    size_t ivSize = gcry_cipher_get_algo_blklen(algorithm);
    size_t keySize = gcry_cipher_get_algo_keylen(algorithm);

    // Set key size to default (256 bits) if the previous call failed
    if (keySize == 0)
        keySize = 32;

    std::vector<unsigned char> salt(SALT_SIZE);
    std::vector<unsigned char> iv(ivSize);
    std::vector<unsigned char> encryptedText;

    // Base64-decode the encoded ciphertext
    std::vector<unsigned char> ciphertext = base64Decode(encodedCiphertext);

    if (ciphertext.size() >= SALT_SIZE + ivSize) [[likely]] {
        // Read the salt and IV from the ciphertext
        salt.assign(ciphertext.begin(), ciphertext.begin() + SALT_SIZE);
        iv.assign(ciphertext.begin() + SALT_SIZE, ciphertext.begin() + SALT_SIZE + static_cast<long>(ivSize));

        encryptedText.assign(ciphertext.begin() + static_cast<long>(salt.size() + iv.size()), ciphertext.end());
    } else
        throw std::runtime_error("invalid ciphertext.");

    size_t encryptedTextSize = encryptedText.size();

    // Derive the key and lock the memory
    std::vector<unsigned char> key = deriveKey(password, salt, static_cast<int>(keySize));
    sodium_mlock(key.data(), key.size());

    // Set up the decryption context
    gcry_error_t err;
    gcry_cipher_hd_t cipherHandle;
    err = gcry_cipher_open(&cipherHandle, algorithm, GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    if (err)
        throw std::runtime_error(std::format("Failed to set up the decryption context: {}", gcry_strerror(err)));

    // Set the decryption key
    err = gcry_cipher_setkey(cipherHandle, key.data(), key.size());
    if (err)
        throw std::runtime_error(std::format("Failed to set the decryption key: {}", gcry_strerror(err)));

    // Key is not needed anymore, zeroize it and unlock it
    sodium_munlock(key.data(), key.size());

    // Set the IV in the decryption context
    err = gcry_cipher_setiv(cipherHandle, iv.data(), iv.size());
    if (err)
        throw std::runtime_error(
                std::format("Failed to set the decryption IV: {}: {}", gcry_strsource(err), gcry_strerror(err)));

    // Decrypt the ciphertext
    std::vector<unsigned char> plaintext(encryptedTextSize);
    err = gcry_cipher_decrypt(cipherHandle, plaintext.data(), plaintext.size(), encryptedText.data(),
                              encryptedTextSize);
    if (err)
        throw std::runtime_error(std::format("Failed to decrypt the ciphertext: {}", gcry_strerror(err)));

    // Clean up the decryption handle's resources
    gcry_cipher_close(cipherHandle);

    // Return the plaintext
    return plaintext.empty() ? "" : std::string(reinterpret_cast<char *>(plaintext.data()), encryptedTextSize);
}

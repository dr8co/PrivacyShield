#include <iostream>
#include <openssl/evp.h>
#include <sodium.h>
#include "cryptoCipher.hpp"
#include "main.hpp"
#include "encryptDecrypt.hpp"

/**
 * @brief encrypts a string using AES256 cipher in CBC mode.
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

    // Generate the salt and the initialization vector (IV)
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
 * @brief decrypts a string using AES256 cipher in CBC mode.
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

    if (ciphertext.size() > SALT_SIZE + ivSize) [[likely]] {
        // Read the salt and IV from the ciphertext
        salt.assign(ciphertext.begin(), ciphertext.begin() + SALT_SIZE);
        iv.assign(ciphertext.begin() + SALT_SIZE, ciphertext.begin() + SALT_SIZE + ivSize);

        encryptedText.assign(ciphertext.begin() + static_cast<long>(salt.size() + iv.size()), ciphertext.end());
    } else
        throw std::runtime_error("invalid ciphertext.");

    // Derive the decryption key from the password and the salt
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

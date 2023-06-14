#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>

constexpr int EVP_SALT_SIZE = 8;
constexpr int MAX_KEY_SIZE = EVP_MAX_KEY_LENGTH;
constexpr int MAX_IV_SIZE = EVP_MAX_IV_LENGTH;
constexpr int CHUNK_SIZE = 1024;


/**
 * generateSalt - Generates a random salt
 * @param saltSize number of bytes of salt to generate
 * @return the generated salt as a vector
 */
std::vector<unsigned char> generateSalt(int saltSize) {
    std::vector<unsigned char> salt(saltSize);
    if (RAND_bytes(salt.data(), saltSize) != 1) {
        std::cerr << "Error generating salt." << std::endl;
        exit(EXIT_FAILURE);
    }
    return salt;
}

/**
 * deriveKey - derives a symmetric key from a password and a salt
 * @param password the password
 * @param salt the salt
 * @return the generated key vector
 */
std::vector<unsigned char> deriveKey(const std::string &password, const std::vector<unsigned char> &salt) {
    std::vector<unsigned char> key(MAX_KEY_SIZE);
    if (PKCS5_PBKDF2_HMAC(password.data(),
                          static_cast<int>(password.size()),
                          salt.data(),
                          static_cast<int>(salt.size()),
                          10000, EVP_sha256(),
                          MAX_KEY_SIZE,
                          key.data()) != 1) {
        std::cerr << "Error deriving key." << std::endl;
        exit(EXIT_FAILURE);
    }
    return key;
}

/**
 * encryptFile - encrypts a file using AES256 in CBC mode.
 * @param inputFile the file to be encrypted.
 * @param outputFile the file to store the encrypted content.
 * @param password the password used to encrypt the file.
 * @return True if encryption succeeds, else False.
 */
bool encryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password) {
    std::vector<unsigned char> salt = generateSalt(EVP_SALT_SIZE);
    std::vector<unsigned char> key = deriveKey(password, salt);

    std::vector<unsigned char> iv(MAX_IV_SIZE);
    if (RAND_bytes(iv.data(), MAX_IV_SIZE) != 1) {
        std::cerr << "Error generating IV." << std::endl;
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        std::cerr << "Error creating cipher context." << std::endl;
        return false;
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctxPtr(ctx, EVP_CIPHER_CTX_free);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        std::cerr << "Error initializing encryption." << std::endl;
        return false;
    }

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
        if (bytesRead <= 0) {
            break;
        }

        if (EVP_EncryptUpdate(ctx, outBuf.data(), &bytesWritten, inBuf.data(), bytesRead) != 1) {
            std::cerr << "Error encrypting data." << std::endl;
            return false;
        }

        outFile.write(reinterpret_cast<const char *>(outBuf.data()), bytesWritten);
        outFile.flush();
    }

    if (EVP_EncryptFinal_ex(ctx, outBuf.data(), &bytesWritten) != 1) {
        std::cerr << "Error finalizing encryption." << std::endl;
        return false;
    }

    outFile.write(reinterpret_cast<const char *>(outBuf.data()), bytesWritten);
    outFile.flush();

    // Close the streams
    inFile.close();
    outFile.close();

    std::cout << "Encryption complete. Encrypted file: " << outputFile << std::endl;

    return true;
}

/**
 * decryptFile - decrypts a file encrypted using AES256 in CBC mode.
 * @param inputFile the file to be decrypted.
 * @param outputFile the file to store the decrypted content.
 * @param password the password used to decrypt the file.
 * @return True if decryption succeeds, else False.
 */
bool decryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password) {
    std::ifstream inFile(inputFile, std::ios::binary);
    std::ofstream outFile(outputFile, std::ios::binary);

    std::vector<unsigned char> salt(EVP_SALT_SIZE);
    std::vector<unsigned char> iv(MAX_IV_SIZE);

    // Read the salt and IV from the input file
    inFile.read(reinterpret_cast<char *>(salt.data()), static_cast<std::streamsize>(salt.size()));
    inFile.read(reinterpret_cast<char *>(iv.data()), static_cast<std::streamsize>(iv.size()));

    std::vector<unsigned char> key = deriveKey(password, salt);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        std::cerr << "Error creating cipher context." << std::endl;
        return false;
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctxPtr(ctx, EVP_CIPHER_CTX_free);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        std::cerr << "Error initializing decryption." << std::endl;
        return false;
    }

    // Set automatic padding handling
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    // Decrypt the file
    std::vector<unsigned char> inBuf(CHUNK_SIZE);
    std::vector<unsigned char> outBuf(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);
    int bytesRead, bytesWritten;

    while (true) {
        inFile.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));
        bytesRead = static_cast<int>(inFile.gcount());
        if (bytesRead <= 0) {
            break;
        }

        if (EVP_DecryptUpdate(ctx, outBuf.data(), &bytesWritten, inBuf.data(), bytesRead) != 1) {
            std::cerr << "Error decrypting data." << std::endl;
            return false;
        }

        outFile.write(reinterpret_cast<const char *>(outBuf.data()), bytesWritten);
        outFile.flush();
    }

    if (EVP_DecryptFinal_ex(ctx, outBuf.data(), &bytesWritten) != 1) {
        std::cerr << "Error finalizing decryption." << std::endl;
        return false;
    }

    outFile.write(reinterpret_cast<const char *>(outBuf.data()), bytesWritten);
    outFile.flush();

    inFile.close();
    outFile.close();

    std::cout << "Decryption complete. Decrypted file: " << outputFile << std::endl;

    return true;
}

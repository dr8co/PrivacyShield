#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <span>
#include <openssl/evp.h>
#include <openssl/rand.h>

/**
 * encryptFile - encrypts a file using AES256 in CBC mode.
 * @param inputFile the file to be encrypted.
 * @param outputFile the file to store the encrypted content.
 * @param password the password used to encrypt the file.
 * @return True if encryption succeeds, else False.
 */
bool encryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password) {
    const int bufferSize = 8192;

    // Initialize OpenSSL library
    OpenSSL_add_all_algorithms();

    // Generate a random initialization vector (IV)
    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
        std::cerr << "Error generating random IV." << std::endl;
        return false;
    }

    // Open the input and output files
    std::ifstream inputFileStream(inputFile, std::ios::binary);
    if (!inputFileStream) {
        std::cerr << "Error opening input file: " << inputFile << std::endl;
        return false;
    }

    std::ofstream outputFileStream(outputFile, std::ios::binary);
    if (!outputFileStream) {
        std::cerr << "Error opening output file: " << outputFile << std::endl;
        return false;
    }

    // Create and initialize the encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, nullptr, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char *>(password.c_str()), iv);

    // Allocate memory for input and output buffers
    std::vector<unsigned char> inBuffer(bufferSize);
    std::vector<unsigned char> outBuffer(bufferSize + EVP_MAX_BLOCK_LENGTH);

    // Read the input file and encrypt its contents
    while (inputFileStream) {
        inputFileStream.read(reinterpret_cast<char *>(inBuffer.data()), bufferSize);
        int bytesRead = inputFileStream.gcount();

        int outLength = 0;
        EVP_EncryptUpdate(ctx, outBuffer.data(), &outLength, inBuffer.data(), bytesRead);
        outputFileStream.write(reinterpret_cast<const char *>(outBuffer.data()), outLength);
    }

    // Finalize the encryption process
    int outLength = 0;
    EVP_EncryptFinal_ex(ctx, outBuffer.data(), &outLength);
    outputFileStream.write(reinterpret_cast<const char *>(outBuffer.data()), outLength);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    inputFileStream.close();
    outputFileStream.close();

    std::cout << "Encryption completed successfully." << std::endl;
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
    const int bufferSize = 8192;

    // Initialize OpenSSL library
    OpenSSL_add_all_algorithms();

    // Open the input and output files
    std::ifstream inputFileStream(inputFile, std::ios::binary);
    if (!inputFileStream) {
        std::cerr << "Error opening input file: " << inputFile << std::endl;
        return false;
    }

    std::ofstream outputFileStream(outputFile, std::ios::binary);
    if (!outputFileStream) {
        std::cerr << "Error opening output file: " << outputFile << std::endl;
        return false;
    }

    // Read the IV from the beginning of the input file
    unsigned char iv[EVP_MAX_IV_LENGTH];
    inputFileStream.read(reinterpret_cast<char *>(iv), EVP_MAX_IV_LENGTH);

    // Create and initialize the decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, nullptr, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char *>(password.c_str()), iv);

    // Adjust the input file reading position
    inputFileStream.seekg(EVP_MAX_IV_LENGTH, std::ios::beg);

    // Allocate memory for input and output buffers
    std::vector<unsigned char> inBuffer(bufferSize);
    std::vector<unsigned char> outBuffer(bufferSize + EVP_MAX_BLOCK_LENGTH);

    // Read the input file and decrypt its contents
    while (inputFileStream) {
        inputFileStream.read(reinterpret_cast<char *>(inBuffer.data()), bufferSize);
        int bytesRead = inputFileStream.gcount();

        int outLength = 0;
        EVP_DecryptUpdate(ctx, outBuffer.data(), &outLength, inBuffer.data(), bytesRead);
        outputFileStream.write(reinterpret_cast<const char *>(outBuffer.data()), outLength);
    }

    // Finalize the decryption process
    int outLength = 0;
    EVP_DecryptFinal_ex(ctx, outBuffer.data(), &outLength);
    outputFileStream.write(reinterpret_cast<const char *>(outBuffer.data()), outLength);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    inputFileStream.close();
    outputFileStream.close();

    std::cout << "Decryption completed successfully." << std::endl;
    return true;
}

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

// Class for OpenSSL cleanup functions
class OpenSSLCleanup {
public:
    OpenSSLCleanup() { OpenSSL_add_all_algorithms(); }

    ~OpenSSLCleanup() { EVP_cleanup(); }
};

// Function to generate a random salt
std::vector<unsigned char> generateSalt(int saltSize) {
    std::vector<unsigned char> salt(saltSize);
    if (RAND_bytes(salt.data(), saltSize) != 1) {
        std::cerr << "Error generating salt." << std::endl;
        exit(EXIT_FAILURE);
    }
    return salt;
}

// Function to derive the symmetric key from the password and salt
std::vector<unsigned char> deriveKey(const std::string &password, const std::vector<unsigned char> &salt) {
    std::vector<unsigned char> key(MAX_KEY_SIZE);
    if (PKCS5_PBKDF2_HMAC(password.data(), password.size(), salt.data(), salt.size(), 10000, EVP_sha256(), MAX_KEY_SIZE,
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
    outFile.write(reinterpret_cast<const char *>(salt.data()), salt.size());
    outFile.write(reinterpret_cast<const char *>(iv.data()), iv.size());

    // Encrypt the file
    std::vector<unsigned char> inBuf(CHUNK_SIZE);
    std::vector<unsigned char> outBuf(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);
    int bytesRead, bytesWritten;

    while (true) {
        inFile.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
        bytesRead = inFile.gcount();
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

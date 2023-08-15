#include <iostream>
#include <random>
#include <fstream>
#include <filesystem>
#include <sodium.h>
#include <readline/readline.h>
#include "../encryption/encryptDecrypt.hpp"
#include "../utils/utils.hpp"

namespace fs = std::filesystem;

/**
 * @brief Checks the strength of a password.
 * @param password the password to process.
 * @return True if the password is strong, False otherwise.
 */
bool isPasswordStrong(const std::string &password) noexcept {
    // Check the length
    if (password.length() < 8) {
        return false;
    }

    // Check for at least one uppercase letter, one lowercase letter, one digit, and one special character.
    bool hasUppercase = false;
    bool hasLowercase = false;
    bool hasDigit = false;
    bool hasPunctuation = false;

    for (char ch: password) {
        if (std::isupper(ch))
            hasUppercase = true;
        else if (std::islower(ch))
            hasLowercase = true;
        else if (std::isdigit(ch))
            hasDigit = true;
        else if (std::ispunct(ch))
            hasPunctuation = true;

        // Break out of the loop as soon as all conditions are satisfied
        if (hasUppercase && hasLowercase && hasDigit && hasPunctuation)
            return true;
    }

    return false;
}

/**
 * @brief Generates a random password.
 * @param length the length of the password.
 * @return a random password.
 */
std::string generatePassword(int length) {
    // a password shouldn't be too short, nor too long
    if (length < 8)
        throw std::length_error("Password too short.");
    if (length > 256)
        throw std::length_error("Password too long.");

    // generate from a set of printable ascii characters
    const std::string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-=_~+[]{}<>";

    // Seed the Mersenne Twister engine with a random source (ideally non-deterministic)
    std::random_device rd;
    std::mt19937_64 generator(rd());

    // Constant probability minimizes predictability
    std::uniform_int_distribution<int> distribution(0, static_cast<int>(characters.size()) - 1);

    std::string password;
    password.reserve(length);

    // Generate a strong password by default
    do {
        password.clear();  // reset the password
        for (int i = 0; i < length; ++i)
            password += characters[distribution(generator)];
    } while (!isPasswordStrong(password));

    return password;
}

/**
 * @brief Hashes a password (using Argon2id implementation from Sodium)
 * for verification without having to store the password.
 * @param password the password to hash.
 * @param opsLimit the maximum amount of computations to perform.
 * @param memLimit the maximum amount of RAM in bytes that the function will use.
 * @return a string of the password hash and it's associated data.
 */
std::string hashPassword(const std::string &password, const size_t &opsLimit, const size_t &memLimit) {
    char hashedPassword[crypto_pwhash_STRBYTES];

    if (crypto_pwhash_str
                (hashedPassword, password.c_str(), password.size(),
                 opsLimit, memLimit) != 0) {
        throw std::runtime_error("Out of memory for password hashing.");
    }

    return std::string{hashedPassword};
}

/**
 * @brief Verifies a password.
 * @param password the password being verified.
 * @param storedHash the hash to verify the password against.
 * @return true if the verification succeeds, else false.
 */
bool verifyPassword(const std::string &password, const std::string &storedHash) {
    return crypto_pwhash_str_verify(storedHash.c_str(),
                                    password.c_str(),
                                    password.size()) == 0;
}


/**
 * @brief Encrypts and then saves passwords to a file.
 * @param passwords a vector of sites and passwords.
 * @param filePath the path where the file is saved.
 * @param encryptionKey the key/password to encrypt the passwords in the process.
 * @return True, if successful.
 */
bool savePasswords(const std::vector<std::pair<std::string, std::string>> &passwords,
                   const std::string &filePath, const std::string &encryptionKey) {
    std::ofstream file(filePath);
    if (!file) {
        std::cerr << "Failed to open the password file for writing." << std::endl;
        return false;
    }

    for (const auto &password: passwords) {
        std::string encryptedPassword = encryptString(password.second, encryptionKey);

        if (encryptedPassword.empty()) {
            std::cerr << "Failed to encrypt password for " << password.first << std::endl;
            return false;
        }

        file << password.first << ":" << std::endl;
        file << encryptedPassword << std::endl;
    }
    file.close();

    return true;
}

/**
 * @brief Loads the encrypted passwords from the disk, and decrypts them.
 * @param filePath path to the password file.
 * @param decryptionKey the key/password to decrypt the passwords.
 * @return decrypted passwords records.
 */
std::vector<std::pair<std::string, std::string>>
loadPasswords(const std::string &filePath, const std::string &decryptionKey) {
    std::vector<std::pair<std::string, std::string>> passwords;

    std::ifstream file(filePath);
    if (!file)
        throw std::runtime_error("Failed to open the password file for reading.");

    std::string line;
    std::string site;
    std::string encryptedPassword;
    bool readingPassword = false;

    while (std::getline(file, line)) {
        if (!readingPassword) {
            std::size_t delimiterPos = line.find(':');

            if (delimiterPos == std::string::npos) {
                std::cerr << "Invalid password entry: " << line << std::endl;
                continue;
            }

            site = line.substr(0, delimiterPos);
            readingPassword = true;
        } else {
            encryptedPassword = line;
            std::string decryptedPassword = decryptString(encryptedPassword, decryptionKey);

            if (decryptedPassword.empty()) {
                std::cerr << "Failed to decrypt password for " << site << std::endl;
                continue;
            }

            passwords.emplace_back(site, decryptedPassword);
            readingPassword = false;
        }
    }

    return passwords;
}

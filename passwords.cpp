#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <readline/readline.h>
#include <openssl/evp.h>
#include <random>
#include <fstream>
#include "main.hpp"

/**
 * @brief reads sensitive input from a terminal without echoing them.
 * @param prompt the prompt to display.
 * @return a string of the information read.
 */
std::string getSensitiveInfo(const std::string &prompt = "") {
    std::string password;
    char *tmp;
    termios oldSettings{}, newSettings{};

    // Turn off terminal echoing
    tcgetattr(STDIN_FILENO, &oldSettings);
    newSettings = oldSettings;
    newSettings.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newSettings);

    // Read password from input
    tmp = readline(prompt.c_str());
    password = std::string(tmp);
    OPENSSL_secure_free(tmp);

    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldSettings);
    std::cout << std::endl;

    return password;
}

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

    // Check for at least one uppercase letter, one lowercase letter, and one digit
    bool hasUppercase = false;
    bool hasLowercase = false;
    bool hasDigit = false;

    for (char ch: password) {
        if (std::isupper(ch))
            hasUppercase = true;
        else if (std::islower(ch))
            hasLowercase = true;
        else if (std::isdigit(ch))
            hasDigit = true;

        // Break out of the loop as soon as all conditions are satisfied
        if (hasUppercase && hasLowercase && hasDigit)
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
    if (length < 1)  // A sanity check won't hurt.
        throw std::length_error("Invalid password length.");

    const std::string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-=_+";

    // Seed the Mersenne Twister engine with a random source (ideally non-deterministic)
    std::random_device rd;
    std::mt19937_64 generator(rd());

    // Uniform probability
    std::uniform_int_distribution<int> distribution(0, static_cast<int>(characters.size()) - 1);

    std::string password;
    password.reserve(length);
    for (int i = 0; i < length; ++i)
        password += characters[distribution(generator)];

    return password;
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
    if (!file)
        throw std::runtime_error("Failed to open the password file for writing.");

    for (const auto &password: passwords) {
        std::string encryptedPassword = encryptString(password.second, encryptionKey);

        if (encryptedPassword.empty())
            throw std::runtime_error("Failed to encrypt password for " + password.first);

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

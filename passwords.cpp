#include <iostream>
#include <random>
#include <fstream>
#include <filesystem>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>
#include <readline/readline.h>
#include "main.hpp"

namespace fs = std::filesystem;

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
    // a password should not be too short, nor too long
    if (length < 8)
        throw std::length_error("Password too short.");
    if (length > 30)
        throw std::length_error("Password too long.");

    // generate from a set of printable ascii characters
    const std::string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-=_~+[]{}<>";

    // Seed the Mersenne Twister engine with a random source (ideally non-deterministic)
    std::random_device rd;
    std::mt19937_64 generator(rd());

    // Uniform probability minimizes predictability
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
 * @param password the password being hashed.
 * @return a string of the password hash and it's associated data.
 */
std::string hashPassword(const std::string &password) {
    char hashedPassword[crypto_pwhash_STRBYTES];

    if (crypto_pwhash_str
                (hashedPassword, password.c_str(), password.size(),
                 crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
        throw std::runtime_error("Out of memory for password hashing.");
    }

    return std::string{hashedPassword};
}

/**
 * @brief verifies a password.
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

/**
 * @brief a minimalistic password manager.
 */
void passwordManager() {
    std::vector<std::pair<std::string, std::string>> passwords;
    std::string passwordFile = "/to/be/determined/later";

    const std::string encryptionKey = getSensitiveInfo("Enter the master password: ");

    if (!encryptionKey.empty() && fs::exists(passwordFile))
        passwords = loadPasswords(passwordFile, encryptionKey);

    while (true) {
        std::cout << "---------------------------" << std::endl;
        std::cout << "1. Add Password" << std::endl;
        std::cout << "2. Generate Password" << std::endl;
        std::cout << "3. View Passwords" << std::endl;
        std::cout << "4. Update Password" << std::endl;
        std::cout << "5. Delete Password" << std::endl;
        std::cout << "6. Save and Exit" << std::endl;
        std::cout << "---------------------------" << std::endl;

        int choice = getResponseInt("Enter your choice: ");

        if (choice == 1) {
            std::string site = getResponseStr("Enter the site/platform: ");

            std::string password = getSensitiveInfo("Enter the password: ");

            if (!isPasswordStrong(password)) {
                std::cout
                        << "Weak password! Password should have at least 8 characters and include uppercase letters, "
                           "lowercase letters, special characters and digits. Please consider updating it."
                        << std::endl;
            }

            std::string encryptedPassword = encryptString(password, encryptionKey);
            passwords.emplace_back(site, encryptedPassword);

            std::cout << "Password added!" << std::endl;
        } else if (choice == 2) {
            int length = getResponseInt("Enter the length of the password to generate: ");

            int tries{0};

            while (length < 8 && tries < 3) {
                std::cout << "A strong password should be at least 8 characters long." << std::endl;
                std::cout << 2 - tries << " Trial(s) left. Try again: ";
                length = getResponseInt();
                ++tries;
            }
            if (tries == 3)
                continue;

            std::string generatedPassword = generatePassword(length);

            std::cout << "Generated password: " << generatedPassword << std::endl;
        } else if (choice == 3) {
            std::cout << "All passwords:" << std::endl;
            for (const auto &password: passwords) {
                std::cout << "Site: " << password.first << std::endl;
                std::cout << "Password: " << decryptString(password.second, encryptionKey) << std::endl;
                std::cout << "--------------------------------" << std::endl;
            }
        } else if (choice == 4) {
            std::string site = getResponseStr("Enter the site to update: ");

            auto it = std::find_if(passwords.begin(), passwords.end(), [&site](const auto &password) {
                return password.first == site;
            });

            if (it != passwords.end()) {
                std::string newPassword = getSensitiveInfo("Enter the new password: ");

                if (!isPasswordStrong(newPassword)) {
                    std::cout
                            << "Weak password! Password should have at least 8 characters and include uppercase letters, "
                               "lowercase letters, special characters, and digits. Please consider using a stronger one."
                            << std::endl;
                }

                it->second = encryptString(newPassword, encryptionKey);
                std::cout << "Password updated!" << std::endl;
            } else {
                std::cout << "Site not found!" << std::endl;
            }
        } else if (choice == 5) {
            std::string site = getResponseStr("Enter the site to delete: ");

            auto it = std::find_if(passwords.begin(), passwords.end(), [&site](const auto &password) {
                return password.first == site;
            });

            if (it != passwords.end()) {
                passwords.erase(it);
                std::cout << "Password deleted!" << std::endl;
            } else {
                std::cout << "Site not found!" << std::endl;
            }
        } else if (choice == 6) {
            savePasswords(passwords, passwordFile, encryptionKey);

            std::cout << "Passwords and encryption key saved!" << std::endl;
            break;
        } else {
            std::cout << "Invalid choice!" << std::endl;
            exit(1);
        }
    }

}

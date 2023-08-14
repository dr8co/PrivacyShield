#include <iostream>
#include <random>
#include <fstream>
#include <filesystem>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>
#include <readline/readline.h>
#include "../encryption/encryptDecrypt.hpp"
#include "../utils/utils.hpp"

namespace fs = std::filesystem;
typedef std::string string;

/**
 * @brief Checks the strength of a password.
 * @param password the password to process.
 * @return True if the password is strong, False otherwise.
 */
bool isPasswordStrong(const string &password) noexcept {
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
string generatePassword(int length) {
    // a password shouldn't be too short, nor too long
    if (length < 8)
        throw std::length_error("Password too short.");
    if (length > 256)
        throw std::length_error("Password too long.");

    // generate from a set of printable ascii characters
    const string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-=_~+[]{}<>";

    // Seed the Mersenne Twister engine with a random source (ideally non-deterministic)
    std::random_device rd;
    std::mt19937_64 generator(rd());

    // Constant probability minimizes predictability
    std::uniform_int_distribution<int> distribution(0, static_cast<int>(characters.size()) - 1);

    string password;
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
string hashPassword(const string &password) {
    char hashedPassword[crypto_pwhash_STRBYTES];

    if (crypto_pwhash_str
                (hashedPassword, password.c_str(), password.size(),
                 crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
        throw std::runtime_error("Out of memory for password hashing.");
    }

    return string{hashedPassword};
}

/**
 * @brief Verifies a password.
 * @param password the password being verified.
 * @param storedHash the hash to verify the password against.
 * @return true if the verification succeeds, else false.
 */
bool verifyPassword(const string &password, const string &storedHash) {
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
bool savePasswords(const std::vector<std::pair<string, string>> &passwords,
                   const string &filePath, const string &encryptionKey) {
    std::ofstream file(filePath);
    if (!file) {
        std::cerr << "Failed to open the password file for writing." << std::endl;
        return false;
    }

    for (const auto &password: passwords) {
        string encryptedPassword = encryptString(password.second, encryptionKey);

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
std::vector<std::pair<string, string>>
loadPasswords(const string &filePath, const string &decryptionKey) {
    std::vector<std::pair<string, string>> passwords;

    std::ifstream file(filePath);
    if (!file)
        throw std::runtime_error("Failed to open the password file for reading.");

    string line;
    string site;
    string encryptedPassword;
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
            string decryptedPassword = decryptString(encryptedPassword, decryptionKey);

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
 * @brief A minimalistic password manager.
 */
void passwordManager() {
    std::vector<std::pair<string, string>> passwords;
    string passwordFile = "/to/be/determined/later";

    string encryptionKey = getSensitiveInfo("Enter the master password: ");

    // Lock the memory area holding the password
    sodium_mlock(encryptionKey.data(), encryptionKey.size());

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
            string site = getResponseStr("Enter the site/platform: ");

            string password = getSensitiveInfo("Enter the password: ");

            if (!isPasswordStrong(password)) {
                std::cout
                        << "Weak password! Password should have at least 8 characters and include uppercase letters,\n"
                           "lowercase letters, special characters and digits.\nPlease consider updating it."
                        << std::endl;
            }

            string encryptedPassword = encryptString(password, encryptionKey);
            passwords.emplace_back(site, encryptedPassword);

            std::cout << "Password added successfully." << std::endl;
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

            string generatedPassword = generatePassword(length);

            std::cout << "Generated password: " << generatedPassword << std::endl;
        } else if (choice == 3) {
            std::cout << "All passwords:" << std::endl;
            for (const auto &password: passwords) {
                std::cout << "Site: " << password.first << std::endl;
                std::cout << "Password: " << decryptString(password.second, encryptionKey) << std::endl;
                std::cout << "--------------------------------" << std::endl;
            }
        } else if (choice == 4) {
            string site = getResponseStr("Enter the site to update: ");

            std::input_iterator auto it = std::ranges::find_if(passwords.begin(), passwords.end(),
                                                               [&site](const auto &password) -> bool {
                                                                   return password.first == site;
                                                               });

            if (it != passwords.end()) {
                string newPassword = getSensitiveInfo("Enter the new password: ");

                if (!isPasswordStrong(newPassword)) {
                    std::cout
                            << "Weak password! Password should have at least 8 characters and include uppercase letters,\n"
                               "lowercase letters, special characters, and digits.\nPlease consider using a stronger one."
                            << std::endl;
                }

                it->second = encryptString(newPassword, encryptionKey);
                std::cout << "Password updated successfully." << std::endl;
            } else {
                std::cout << "Site not found!" << std::endl;
            }
        } else if (choice == 5) {
            string site = getResponseStr("Enter the site to delete: ");

            std::input_iterator auto it = std::ranges::find_if(passwords.begin(), passwords.end(),
                                                               [&site](const auto &password) -> bool {
                                                                   return password.first == site;
                                                               });

            if (it != passwords.end()) {
                passwords.erase(it);
                std::cout << "Password deleted!" << std::endl;
            } else {
                std::cout << "Site not found!" << std::endl;
            }
        } else if (choice == 6) {
            break;
        } else {
            std::cout << "Invalid choice!" << std::endl;
        }
    }
    (savePasswords(passwords, passwordFile, encryptionKey) ? std::cout << "Passwords saved!" : std::cerr
            << "Passwords not saved!") << std::endl;

    // Zero the password data and unlock the memory area
    sodium_munlock((void *) encryptionKey.data(), encryptionKey.size());

}

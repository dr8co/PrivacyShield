#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <readline/readline.h>
#include <openssl/evp.h>
#include <random>

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
    const std::string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-=_+";

    std::random_device rd;
    std::mt19937_64 generator(rd());

    std::uniform_int_distribution<int> distribution(0, static_cast<int>(characters.size()) - 1);

    std::string password;
    password.reserve(length);
    for (int i = 0; i < length; ++i) {
        password += characters[distribution(generator)];
    }

    return password;
}

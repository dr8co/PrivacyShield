// Privacy Shield: A Suite of Tools Designed to Facilitate Privacy Management.
// Copyright (C) 2024  Ian Duncan <dr8co@duck.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see https://www.gnu.org/licenses.
module;

#include <charconv>
#include <readline/readline.h>
#include <unistd.h>
#include <utility>
#include <termios.h>
#include <optional>
#include <iostream>
#include <filesystem>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <vector>
#include <sodium.h>
#include <print>

module utils;

import secureAllocator;

constexpr int MAX_PASSPHRASE_LEN = 1024; // Maximum length of a passphrase

/// \brief Performs Base64 decoding of a string into binary data.
/// \param encodedData Base64 encoded string.
/// \return a vector of the decoded binary data.
/// \throws std::bad_alloc if memory allocation fails.
/// \throws std::runtime_error if the decoding operation fails.
std::vector<unsigned char> base64Decode(const std::string_view encodedData) {
    // Create a BIO object to decode the data
    std::unique_ptr<BIO, decltype(&BIO_free_all)> bio(
        BIO_new_mem_buf(encodedData.data(), static_cast<int>(encodedData.size())), &BIO_free_all);
    if (bio == nullptr)
        throw std::bad_alloc(); // Memory allocation failed

    // Create a base64 BIO
    BIO *b64 = BIO_new(BIO_f_base64());
    if (b64 == nullptr)
        throw std::bad_alloc(); // Memory allocation failed

    // Don't use newlines to flush buffer
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    // Push the base64 BIO to the memory BIO
    bio.reset(BIO_push(b64, bio.release())); // Transfer ownership to bio

    std::vector<unsigned char> decodedData(encodedData.size());

    // Decode the data
    const int len = BIO_read(bio.get(), decodedData.data(), static_cast<int>(decodedData.size()));
    if (len < 0)
        throw std::runtime_error("BIO_read() failed.");

    // Resize to the actual length of the decoded data
    decodedData.resize(len);

    return decodedData;
}

// This concept checks if the type provides the functionality of a string
template<typename T>
concept StringLike = std::same_as<T, std::basic_string<typename T::value_type,
    typename T::traits_type, typename T::allocator_type> >;

/// \brief Trims space (whitespace) off the beginning and end of a string.
/// \param str the string to trim.
void stripString(StringLike auto &str) noexcept {
    constexpr std::string_view space = " \t\n\r\f\v";

    // Trim the leading space
    str.erase(0, str.find_first_not_of(space));

    // Trim the trailing space
    str.erase(str.find_last_not_of(space) + 1);
}

/// \brief Gets a response string from user input.
///
/// This function prompts the user with the given prompt and reads a response string
/// from the standard input.
///
/// \param prompt The prompt to display to the user.
/// \return The response string entered by the user if successful, else nullptr.
std::string getResponseStr(const std::string_view prompt) {
    std::cout << prompt << std::endl;
    char *tmp = readline("> ");
    if (tmp == nullptr) return std::string{};

    auto str = std::string{tmp};

    // Trim leading and trailing spaces
    stripString(str);

    // tmp must be freed
    std::free(tmp);

    return str;
}

/// \brief Captures the user's response while offering editing capabilities.
/// while the user is entering the data.
/// \param prompt the prompt displayed to the user for the input.
/// \return the user's input (an integer) on if it's convertible to integer, else 0.
int getResponseInt(const std::string_view prompt) {
    // A lambda to convert a string to an integer
    constexpr auto toInt = [](const std::string_view s) noexcept -> int {
        int value;
        return std::from_chars(s.begin(), s.end(), value).ec == std::errc{} ? value : 0;
    };

    return toInt(getResponseStr(prompt));
}

/// \brief Reads sensitive input from a terminal without echoing them.
/// \param prompt the prompt to display.
/// \return the user's input.
/// \throws std::bad_alloc if memory allocation fails.
/// \throws std::runtime_error if memory locking/unlocking fails.
privacy::string getSensitiveInfo(const std::string_view prompt) {
    // Allocate a buffer for the password
    auto *buffer = static_cast<char *>(sodium_malloc(MAX_PASSPHRASE_LEN));
    if (buffer == nullptr)
        throw std::bad_alloc(); // Memory allocation failed

    // Lock the memory to prevent swapping
    if (sodium_mlock(buffer, MAX_PASSPHRASE_LEN) == -1) {
        sodium_free(buffer);
        throw std::runtime_error("Failed to lock memory.");
    }

    // Turn off terminal echoing
    termios oldSettings{}, newSettings{};

    tcgetattr(STDIN_FILENO, &oldSettings);
    newSettings = oldSettings;
    newSettings.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newSettings);

    // Prompt the user for the password
    std::cout << prompt;

    int index = 0; // current position in the buffer
    char ch;
    while (std::cin.get(ch) && ch != '\n') {
        // check for backspace
        if (ch == '\b') {
            if (index > 0) {
                --index; // move back one position in the buffer
            }
        } else {
            // Check if buffer is not full
            if (index < MAX_PASSPHRASE_LEN - 1) {
                buffer[index++] = ch;
            }
        }
    }
    buffer[index] = '\0'; // Null-terminate the string

    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldSettings);

    privacy::string passphrase{buffer};

    // Unlock the memory
    if (sodium_munlock(buffer, MAX_PASSPHRASE_LEN) == -1)
        throw std::runtime_error("Failed to unlock memory.");

    // Free the buffer
    sodium_free(buffer);

    // Trim leading and trailing spaces
    stripString(passphrase);

    std::cout << std::endl;

    return passphrase;
}

/// \brief Confirms a user's response to a yes/no (y/n) situation.
/// \param prompt The confirmation prompt.
/// \return True if the user confirms the action, else false.
bool validateYesNo(const std::string_view prompt) {
    const std::string resp = getResponseStr(prompt);
    if (resp.empty()) return false;
    return std::tolower(resp.at(0)) == 'y';
}

/// \brief Checks if an existing file grants write permissions.
/// to the current user.
/// \param filename the path to the file.
/// \return true if the current user has write permissions, else false.
bool isWritable(const std::string &filename) {
    return access(filename.c_str(), F_OK | W_OK) == 0;
}

/// \brief Checks if an existing file grants read permissions.
/// to the current user.
/// \param filename the path to the file.
/// \return true if the current user has read permissions, else false.
bool isReadable(const std::string &filename) {
    return access(filename.c_str(), F_OK | R_OK) == 0;
}

/// \brief Checks the available space on disk.
/// \param path The path to check.
/// \return The available space in bytes.
///
/// \warning This function does not throw, and returns 0 in case of an error.
/// \note This function is meant to be used to detect possible errors
/// early enough before file operations, and to warn the user to
/// check their filesystem storage space when it seems insufficient.
std::uintmax_t getAvailableSpace(const fs::path &path) noexcept {
    fs::path filePath{path};

    std::error_code ec; // For ignoring errors to avoid throwing

    // Find an existing component of the path
    while ((!exists(filePath, ec)) && filePath.has_parent_path())
        filePath = filePath.parent_path();
    if (ec) ec.clear();

    auto [capacity, free, available] = space(canonical(filePath, ec), ec);

    // Return 0 in case of an error
    return std::cmp_less(available, 0) || std::cmp_equal(available, UINTMAX_MAX) ? 0 : available;
}


/// \brief Copies a file's permissions to another, replacing if necessary.
/// \param srcFile The source file.
/// \param destFile The destination file.
/// \return True if the operation is successful, else false.
///
/// \note This function is only needed for the preservation of file permissions
/// during encryption and decryption.
bool copyFilePermissions(const std::string_view srcFile, const std::string_view destFile) noexcept {
    std::error_code ec;
    // Get the permissions of the input file
    const auto permissions = fs::status(srcFile, ec).permissions();
    if (ec) return false;

    // Set the permissions to the output file
    fs::permissions(destFile, permissions, fs::perm_options::replace, ec);
    if (ec) return false;

    return true;
}

/// \brief Gets the value of an environment variable.
/// \param var an environment variable to query.
/// \return the value of the environment variable if it exists, else nullopt (nothing).
/// \note The returned value MUST be checked before access.
std::optional<std::string> getEnv(const char *const var) {
    // Use secure_getenv() if available
#if _GNU_SOURCE
    if (const char *value = secure_getenv(var))
        return value;
#else
    if (const char *value = std::getenv(var))
        return value;
#endif
    return std::nullopt;
}

/// \brief Retrieves the user's home directory
/// \return The home directory read from {'HOME', 'USERPROFILE'}
/// environment variables, else the current working directory (or an empty
/// string if the current directory couldn't be determined).
std::string getHomeDir() noexcept {
    std::error_code ec;
    // Try to get the home directory from the environment variables
    if (const auto envHome = getEnv("HOME"); envHome)
        return *envHome;
    if (const auto envUserProfile = getEnv("USERPROFILE"); envUserProfile)
        return *envUserProfile;

    // If the environment variables are not set, use the current working directory
    std::cerr << "\nCouldn't find your home directory, using the current working directory instead.." << std::endl;

    std::string currentDir = std::filesystem::current_path(ec);
    if (ec) std::cerr << ec.message() << std::endl;

    return currentDir;
}

/// \brief Configures the color output of the terminal.
/// \param disable a flag to indicate whether color output should be disabled.
void configureColor(const bool disable) noexcept {
    // Check if the user has requested no color
    if (disable) {
        ColorConfig::getInstance().setSuppressColor(true);
        return;
    }
    // Process the environment variable to suppress color output
    const auto noColorEnv = getEnv("NO_COLOR");
    const auto termEnv = getEnv("TERM");
    const bool suppressColor = noColorEnv.has_value() ||
                               (termEnv.has_value() && (termEnv.value() == "dumb" || termEnv.value() == "vt100" ||
                                                        termEnv.value() == "vt102"));
    ColorConfig::getInstance().setSuppressColor(suppressColor);
}

#include <charconv>
#include <vector>
#include <readline/readline.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <iostream>
#include "utils.hpp"
#include <filesystem>
#include <utility>
#include <termios.h>
#include <optional>

namespace fs = std::filesystem;


/**
 * @brief Performs Base64 encoding of binary data into a string.
 * @param input a vector of the binary data to be encoded.
 * @return Base64-encoded string.
 */
std::string base64Encode(const std::vector<unsigned char> &input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_new(BIO_s_mem());

    if (b64 == nullptr || bio == nullptr)
        throw std::bad_alloc();  // Memory allocation failed

    b64 = BIO_push(b64, bio);

    if (BIO_write(b64, input.data(), static_cast<int>(input.size())) < 0)
        throw std::runtime_error("BIO_write() failed.");

    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);

    std::string encodedData(bufferPtr->data, bufferPtr->length);
    BIO_free_all(b64);

    return encodedData;
}

/**
 * @brief Performs Base64 decoding of a string into binary data.
 * @param encodedData Base64 encoded string.
 * @return a vector of the decoded binary data.
 */
std::vector<unsigned char> base64Decode(const std::string &encodedData) {
    BIO *bio, *b64;
    int len;

    std::vector<unsigned char> decodedData(encodedData.size());

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(encodedData.data(), static_cast<int>(encodedData.size()));

    if (b64 == nullptr || bio == nullptr)
        throw std::bad_alloc();  // Memory allocation failed

    bio = BIO_push(b64, bio);

    len = BIO_read(bio, decodedData.data(), static_cast<int>(decodedData.size()));

    if (len < 0)
        throw std::runtime_error("BIO_read() failed.");

    BIO_free_all(bio);

    decodedData.resize(len);

    return decodedData;
}

/**
 * @brief Trims space (whitespace) off the beginning and end of a string.
 * @param str the string to trim.
 */
inline void trimSpace(std::string &str) {
    // Trim the leading space (my IDE finds the w-word offensive)
    std::input_iterator auto it = std::ranges::find_if_not(str.begin(), str.end(),
                                                           [](char c) { return std::isspace(c); });
    str.erase(str.begin(), it);

    // Trim the trailing space
    it = std::ranges::find_if_not(str.rbegin(), str.rend(), [](char c) { return std::isspace(c); }).base();
    str.erase(it, str.end());
}

/**
 * @brief Captures the user's response while offering editing capabilities
 * while the user is entering the data.
 * @param prompt the prompt displayed to the user for the input.
 * @return the user's input (string) if successful, else nullptr.
 */
std::string getResponseStr(const std::string &prompt) {
    std::cout << prompt << std::endl;
    char *tmp = readline("> ");
    auto str = std::string{tmp};

    // Trim leading and trailing spaces
    trimSpace(str);

    // tmp must be freed
    free(tmp);

    return str;
}

/**
 * @brief Captures the user's response while offering editing capabilities.
 * while the user is entering the data.
 * @param prompt the prompt displayed to the user for the input.
 * @return the user's input (an integer) on if it's convertible to integer, else 0.
 */
int getResponseInt(const std::string &prompt) {
    constexpr auto toInt = [](std::string_view s) noexcept -> int {
        int value;
        return std::from_chars(s.begin(), s.end(), value).ec == std::errc{} ? value : 0;
    };

    return toInt(getResponseStr(prompt));
}

/**
 * @brief Reads sensitive input from a terminal without echoing them.
 * @param prompt the prompt to display.
 * @return the user's input.
 */
std::string getSensitiveInfo(const std::string &prompt) {
    termios oldSettings{}, newSettings{};

    // Turn off terminal echoing
    tcgetattr(STDIN_FILENO, &oldSettings);
    newSettings = oldSettings;
    newSettings.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newSettings);

    // Read password from input
    char *tmp = readline(prompt.c_str());
    std::string secret{tmp};
    std::free(tmp);

    // Trim leading and trailing spaces
    trimSpace(secret);

    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldSettings);
    std::cout << std::endl;

    return secret;
}

/**
 * @brief Confirms a user's response to a yes/no (y/n) situation.
 * @param prompt The confirmation prompt.
 * @return True if the user confirms the action, else false.
 */
bool validateYesNo(const std::string &prompt) {
    std::string resp = getResponseStr(prompt);
    if (resp.empty()) return false;
    return std::tolower(resp.at(0)) == 'y';
}

/**
 * @brief Checks if an existing file grants write permissions.
 * to the current user.
 * @param filename the path to the file.
 * @return true if the current user has write permissions, else false.
 */
bool isWritable(const std::string &filename) {
    return access(filename.c_str(), F_OK | W_OK) == 0;
}

/**
 * @brief Checks if an existing file grants read permissions.
 * to the current user.
 * @param filename the path to the file.
 * @return true if the current user has read permissions, else false.
 */
bool isReadable(const std::string &filename) {
    return access(filename.c_str(), F_OK | R_OK) == 0;
}

/**
 * @brief handles file i/o errors during low-level file operations.
 * @param filename path to the file on which an error occurred.
 */
void handleAccessError(const std::string &filename) {
    switch (errno) {
        case EACCES:        // Permission denied
            std::cerr << "Error: '" << filename << "': You do not have permission to access this file." << std::endl;
            break;
        case EEXIST:        // File exists
            std::cerr << "Error: '" << filename << "' already exists." << std::endl;
            break;
        case EISDIR:        // Is a directory
            std::cerr << "Error: '" << filename << "' is a directory." << std::endl;
            break;
        case ELOOP:         // Too many symbolic links encountered
            std::cerr << "Error: '" << filename << "' is a loop." << std::endl;
            break;
        case ENAMETOOLONG:  // The filename is too long
            std::cerr << "Error: '" << filename << "' is too long." << std::endl;
            break;
        case ENOENT:        // No such file or directory
            std::cerr << "Error: '" << filename << "' does not exist." << std::endl;
            break;
        case EROFS:         // Read-only file system
            std::cerr << "Error: '" << filename << "' is read-only." << std::endl;
            break;
        default:            // Success (most likely)
            return;
    }
}

/**
 * @brief Checks the available space on disk.
 * @param path The path to check.
 * @return The available space in bytes.
 *
 * @warning This function does not throw, and returns 0 in case of an error.
 * @note This function is meant to be used to detect possible errors
 * early enough before file operations, and to warn the user to
 * check their filesystem storage space when it seems insufficient.
 */
std::uintmax_t getAvailableSpace(const std::string &path) noexcept {
    fs::path filePath(path);

    std::error_code ec; // For ignoring errors to avoid throwing
    fs::space_info space{};

    // Find an existing component of the path
    while ((!fs::exists(filePath, ec)) && filePath.has_parent_path())
        filePath = filePath.parent_path();
    if (ec) ec.clear();

    space = fs::space(filePath, ec);

    // -1 should be returned if an error occurs, but it wraps on some systems,
    // or maybe just mine.
    return std::cmp_less(space.available, 0) || std::cmp_equal(space.available, UINTMAX_MAX) ? 0 : space.available;
}

/**
 * @brief Copies a file's permissions to another, replacing if necessary.
 * @param srcFile The source file.
 * @param destFile The destination file.
 * @return True if the operation is successful, else false.
 *
 * @note This function is only needed for the preservation of file permissions
 * during encryption and decryption.
 */
bool copyFilePermissions(const std::string &srcFile, const std::string &destFile) noexcept {
    std::error_code ec;
    // Get the permissions of the input file
    const auto permissions = fs::status(srcFile, ec).permissions();
    if (ec) return false;

    // Set the permissions to the output file
    fs::permissions(destFile, permissions, fs::perm_options::replace, ec);
    if (ec) return false;

    return true;
}

/**
 * @brief Gets the value of an environment variable.
 * @param var an environment variable to query.
 * @return the value of the environment variable if it exists, else nullopt (nothing).
 * @note The returned value MUST be checked before access.
 */
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

/**
 * @brief Retrieves the user's home directory
 * @return The home directory read from {'HOME', 'USERPROFILE'}
 * environment variables, else the current working directory (or an empty
 * string if the current directory couldn't be determined).
 */
std::string getHomeDir() noexcept {
    std::error_code ec;
    if (auto envHome = getEnv("HOME"); envHome)
        return *envHome;
    if (auto envUserProfile = getEnv("USERPROFILE"); envUserProfile)
        return *envUserProfile;

    std::cerr << "\nCouldn't find your home directory, using the current working directory instead.." << std::endl;

    std::string currentDir = std::filesystem::current_path(ec);
    if (ec) std::cerr << ec.message() << std::endl;

    return currentDir;
}

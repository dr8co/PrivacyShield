#include <iomanip>
#include <charconv>
#include <vector>
#include <readline/readline.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <iostream>
#include <map>


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
 * @brief Performs Hex encoding.
 * @param data binary data to be encoded.
 * @return the encoded string.
 */
std::string hexEncode(const std::vector<unsigned char> &data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (const auto &byte: data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

/**
 * @brief Performs Hex decoding.
 * @param encodedData Hex encoded string.
 * @return binary data.
 */
std::vector<unsigned char> hexDecode(const std::string &encodedData) {
    std::vector<unsigned char> decoded_data(encodedData.length() / 2);

    for (size_t i = 0; i < encodedData.length(); i += 2) {
        std::stringstream ss;
        ss << std::hex << encodedData.substr(i, 2);
        int byte_value;
        ss >> byte_value;
        decoded_data[i / 2] = static_cast<unsigned char>(byte_value);
    }
    return decoded_data;
}

/**
 * @brief Captures the user's response while offering editing capabilities
 * while the user is entering the data.
 * @param prompt the prompt displayed to the user for the input.
 * @return the user's input (string) if successful, else nullptr.
 */
std::string getResponseStr(const std::string &prompt) {
    char *tmp = readline(prompt.c_str());
    auto str = std::string(tmp);

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
    constexpr auto to_int = [](std::string_view s) noexcept -> int {
        int value;
        return std::from_chars(s.begin(), s.end(), value).ec == std::errc{} ? value : 0;
    };

    return to_int(getResponseStr(prompt));
}

/**
 * @brief Checks if an existing file is writable.
 * @param filename the path to the file.
 * @return true if the file is writable, else false.
 */
inline bool isWritable(const std::string &filename) {
    return access(filename.c_str(), F_OK | W_OK) == 0;
}

/**
 * @brief Checks if an existing file is readable.
 * @param filename the path to the file.
 * @return true if the file is readable, else false.
 */
inline bool isReadable(const std::string &filename) {
    return access(filename.c_str(), F_OK | R_OK) == 0;
}

/**
 * @brief handles file i/o errors during low-level file operations.
 * @param filename path to the file on which an error occurred.
 */
inline void handleFileIoErrno(const std::string &filename) {
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
        default:
            return;
    }
}

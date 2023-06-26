#include <string>
#include <vector>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <readline/readline.h>

/**
 * @brief Performs base64 encoding.
 * @param input the binary string to be encoded.
 * @return the encoded string.
 */
std::string base64Encode(const std::string &input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());

    if (b64 == nullptr || bio == nullptr)
        throw std::bad_alloc();  // Memory allocation failed

    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    if (BIO_write(bio, input.data(), static_cast<int>(input.size())) < 0)
        throw std::runtime_error("BIO_write() failed.");

    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encodedData(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return encodedData;
}

/**
 * @brief Performs Base64 decoding.
 * @param encodedData Base64 encoded string.
 * @return binary string.
 */
std::string base64Decode(const std::string &encodedData) {
    BIO *bio, *b64;

    std::vector<unsigned char> decodedData(encodedData.size());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encodedData.data(), static_cast<int>(encodedData.size()));

    if (b64 == nullptr || bio == nullptr)
        throw std::bad_alloc();  // Memory allocation failed

    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    if (BIO_read(bio, decodedData.data(), static_cast<int>(decodedData.size())) < 0)
        throw std::runtime_error("BIO_read() failed.");

    BIO_free_all(bio);

    return reinterpret_cast<const char *>(decodedData.data());
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
std::string getResponseStr(const std::string &prompt = "") {
    char *tmp;
    std::string str;

    tmp = readline(prompt.c_str());
    str = std::string(tmp);

    // tmp must be freed
    free(tmp);

    return str;
}

/**
 * @brief Captures the user's response while offering editing capabilities
 * while the user is entering the data.
 * @param prompt the prompt displayed to the user for the input.
 * @return the user's input (an integer) on success, else 0.
 */
int getResponseInt(const std::string &prompt = "") {
    int num{0};
    const std::string str = getResponseStr(prompt);

    // Convert string to int
    errno = 0;
    num = static_cast<int>(std::strtol(str.c_str(), nullptr, 10));

    // Return 0 on any conversion error, and suppress the error message
    if (errno != 0)
        return 0;

    return num;

}

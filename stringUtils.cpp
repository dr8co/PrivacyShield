#include <string>
#include <vector>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/buffer.h>

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
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.data(), static_cast<int>(input.size()));
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
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_read(bio, decodedData.data(), static_cast<int>(decodedData.size()));

    BIO_free_all(bio);

    return reinterpret_cast<const char *>(decodedData.data());
}

#pragma once

#include <cstdint>
#include <optional>
#include <iostream>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include "../secureAllocator.hpp"

template<typename T>
// Describes a type that can be formatted to the output stream
concept PrintableToStream = requires(std::ostream &os, const T &t) {
    os << t;
};

/**
 * @brief Prints colored text to a stream.
 * @param text the text to print.
 * @param color a character representing the desired color.
 * @param printNewLine a flag to indicate whether a newline should be printed after the text.
 * @param os the stream object to print to.
 */
void printColor(const PrintableToStream auto &text, const char &color = 'w', const bool &printNewLine = false,
                std::ostream &os = std::cout) {
    switch (color) {
        case 'r': // Red
            os << "\033[1;31m";
            break;
        case 'g': // Green
            os << "\033[1;32m";
            break;
        case 'y': // Yellow
            os << "\033[1;33m";
            break;
        case 'b': // Blue
            os << "\033[1;34m";
            break;
        case 'm': // Magenta
            os << "\033[1;35m";
            break;
        case 'c': // Cyan
            os << "\033[1;36m";
            break;
        case 'w': // White
            os << "\033[1;37m";
            break;
        default:
            break;
    }
    os << text << "\033[0m";
    if (printNewLine)
        os << std::endl;
}

template<typename T>
// Describes a vector of unsigned characters (For use with vectors using different allocators)
concept uCharVector = std::copy_constructible<T> && requires(T t, unsigned char c) {
    { t.data() } -> std::same_as<unsigned char *>;
    { t.size() } -> std::integral;
    { t.capacity() } -> std::integral;
    std::is_same_v<decltype(t[0]), unsigned char>;
    t.push_back(c);
    t.emplace_back(c);
    t.shrink_to_fit();
};

/**
 * @brief Performs Base64 encoding of binary data into a string.
 * @param input a vector of the binary data to be encoded.
 * @return Base64-encoded string.
 */
std::string base64Encode(const uCharVector auto &input) {
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

std::vector<unsigned char> base64Decode(const std::string &encodedData);

int getResponseInt(const std::string &prompt = "");

std::string getResponseStr(const std::string &prompt = "");

bool isWritable(const std::string &filename);

bool isReadable(const std::string &filename);

std::uintmax_t getAvailableSpace(const std::string &path) noexcept;

bool copyFilePermissions(const std::string &srcFile, const std::string &destFile) noexcept;

privacy::string getSensitiveInfo(const std::string &prompt = "");

bool validateYesNo(const std::string &prompt = "");

std::string getHomeDir() noexcept;

std::optional<std::string> getEnv(const char *var);

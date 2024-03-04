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

#include <optional>
#include <iostream>
#include <filesystem>
#include <unordered_map>
#include <vector>
#include <openssl/buffer.h>
#include <openssl/evp.h>

export module utils;

import secureAllocator;

namespace fs = std::filesystem;

static const std::unordered_map<char, const char *const> COLOR = {
    {'r', "\033[1;31m"}, // Red
    {'g', "\033[1;32m"}, // Green
    {'y', "\033[1;33m"}, // Yellow
    {'b', "\033[1;34m"}, // Blue
    {'m', "\033[1;35m"}, // Magenta
    {'c', "\033[1;36m"}, // Cyan
    {'w', "\033[1;37m"}, // White
};

template<typename T>
// Describes a type that can be formatted to the output stream
concept PrintableToStream = requires(std::ostream &os, const T &t) {
    os << t;
};

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

export {

    /// \brief Prints colored text to a stream.
    /// \param text the text to print.
    /// \param color a character representing the desired color.
    /// \param printNewLine a flag to indicate whether a newline should be printed after the text.
    /// \param os the stream object to print to.
    void printColor(const PrintableToStream auto &text, const char &color = 'w', const bool &printNewLine = false,
                    std::ostream &os = std::cout) {
        // Print the text in the desired color
        os << (COLOR.contains(color) ? COLOR.at(color) : "") << text << "\033[0m";

        // Print a newline if requested
        if (printNewLine) os << std::endl;
    }

    /// \brief Performs Base64 encoding of binary data into a string.
    /// \param input a vector of the binary data to be encoded.
    /// \return Base64-encoded string.
    /// \throws std::bad_alloc if memory allocation fails.
    /// \throws std::runtime_error if encoding fails.
    std::string base64Encode(const uCharVector auto &input) {
        // Create a BIO object to encode the data
        const std::unique_ptr<BIO, decltype(&BIO_free_all)> b64(BIO_new(BIO_f_base64()), &BIO_free_all);
        if (b64 == nullptr)
            throw std::bad_alloc(); // Memory allocation failed

        // Create a memory BIO to store the encoded data
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio == nullptr)
            throw std::bad_alloc(); // Memory allocation failed

        // Don't use newlines to flush buffer
        BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);

        // Push the memory BIO to the base64 BIO
        bio = BIO_push(b64.get(), bio); // Transfer ownership to b64

        // Write the data to the BIO
        if (BIO_write(bio, input.data(), static_cast<int>(input.size())) < 0)
            throw std::runtime_error("BIO_write() failed.");

        // Flush the BIO
        BIO_flush(bio);

        // Get the pointer to the BIO's data
        BUF_MEM *bufferPtr;
        BIO_get_mem_ptr(b64.get(), &bufferPtr);

        // Create a string from the data
        std::string encodedData(bufferPtr->data, bufferPtr->length);

        return encodedData;
    }

    std::vector<unsigned char> base64Decode(std::string_view encodedData);

    int getResponseInt(std::string_view prompt = "");

    std::string getResponseStr(std::string_view prompt = "");

    bool isWritable(const std::string &filename);

    bool isReadable(const std::string &filename);

    std::uintmax_t getAvailableSpace(const fs::path &path) noexcept;

    bool copyFilePermissions(std::string_view srcFile, std::string_view destFile) noexcept;

    privacy::string getSensitiveInfo(std::string_view prompt = "");

    bool validateYesNo(std::string_view prompt = "");

    std::string getHomeDir() noexcept;

    std::optional<std::string> getEnv(const char *var);
}

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


/// \class ColorConfig
/// \brief A singleton class used to manage the color configuration of the terminal output.
/// This class encapsulates the \p suppressColor functionality, ensuring that there is only
/// one \p suppressColor instance throughout the application.
/// It provides methods to get and set the \p suppressColor value.
class ColorConfig {
public:
    /// \brief Gets the instance of the \p ColorConfig singleton.
    /// \return A reference to the singleton instance of the \p ColorConfig class.
    static ColorConfig &getInstance() noexcept {
        static ColorConfig instance;
        return instance;
    }

    // Delete the copy constructor and assignment operator
    ColorConfig(ColorConfig const &) = delete;

    void operator=(ColorConfig const &) = delete;

    /// \brief Gets the \p suppressColor value.
    /// \return The current value of the \p suppressColor variable.
    [[nodiscard]] bool getSuppressColor() const noexcept {
        return suppressColor;
    }

    /// \brief Sets the \p suppressColor value.
    /// \param value The new value for the \p suppressColor variable.
    void setSuppressColor(const bool value) noexcept {
        suppressColor = value;
    }

private:
    /// \brief Private constructor for the \p ColorConfig class.
    /// This constructor initializes the \p suppressColor variable to false.
    ColorConfig() : suppressColor(false) {
    }

    // The suppressColor value
    bool suppressColor;
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

/// \brief Returns the ANSI color code for the given character.
/// \param color The character representing the color.
/// \return The ANSI color code corresponding to the input character.
constexpr const char *getColorCode(const char color) noexcept {
    switch (color) {
        case 'r': // Red
            return "\033[1;31m";
        case 'g': // Green
            return "\033[1;32m";
        case 'y': // Yellow
            return "\033[1;33m";
        case 'b': // Blue
            return "\033[1;34m";
        case 'm': // Magenta
            return "\033[1;35m";
        case 'c': // Cyan
            return "\033[1;36m";
        case 'w': // White
            return "\033[1;37m";
        default: // No color
            return "";
    }
}

export {
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

    /// \brief Prints colored output to the console.
    /// \tparam Args Variadic template for all types of arguments that can be passed.
    /// \param color The color code for the output.
    /// \param fmt The format string for the output.
    /// \param args The arguments to be printed.
    template<class... Args>
    void printColoredOutput(const char color, std::format_string<Args...> fmt, Args &&... args) {
        if (ColorConfig::getInstance().getSuppressColor())
            std::cout << std::vformat(fmt.get(), std::make_format_args(args...));
        else std::cout << getColorCode(color) << std::vformat(fmt.get(), std::make_format_args(args...)) << "\033[0m";
    }

    /// \brief Prints colored output to the console and adds a newline at the end.
    /// \tparam Args Variadic template for all types of arguments that can be passed.
    /// \param color The color code for the output.
    /// \param fmt The format string for the output.
    /// \param args The arguments to be printed.
    template<class... Args>
    void printColoredOutputln(const char color, std::format_string<Args...> fmt, Args &&... args) {
        if (ColorConfig::getInstance().getSuppressColor())
            std::cout << std::vformat(fmt.get(), std::make_format_args(args...)) << std::endl;
        else
            std::cout << getColorCode(color) << std::vformat(fmt.get(), std::make_format_args(args...)) << "\033[0m" <<
                    std::endl;
    }

    /// \brief Prints colored error messages to the console.
    /// \tparam Args Variadic template for all types of arguments that can be passed.
    /// \param color The color code for the output.
    /// \param fmt The format string for the output.
    /// \param args The arguments to be printed.
    template<class... Args>
    void printColoredError(const char color, std::format_string<Args...> fmt, Args &&... args) {
        if (ColorConfig::getInstance().getSuppressColor())
            std::cerr << std::vformat(fmt.get(), std::make_format_args(args...));
        else std::cerr << getColorCode(color) << std::vformat(fmt.get(), std::make_format_args(args...)) << "\033[0m";
    }

    /// \brief This function prints colored error messages to the console and adds a newline at the end.
    /// \tparam Args Variadic template for all types of arguments that can be passed.
    /// \param color The color code for the output.
    /// \param fmt The format string for the output.
    /// \param args The arguments to be printed.
    template<class... Args>
    void printColoredErrorln(const char color, std::format_string<Args...> fmt, Args &&... args) {
        if (ColorConfig::getInstance().getSuppressColor())
            std::cerr << std::vformat(fmt.get(), std::make_format_args(args...)) << std::endl;
        else
            std::cerr << getColorCode(color) << std::vformat(fmt.get(), std::make_format_args(args...)) << "\033[0m" <<
                    std::endl;
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

    void configureColor(bool disable = false) noexcept;
}

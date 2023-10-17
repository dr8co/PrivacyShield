// Privacy Shield: A Suite of Tools Designed to Facilitate Privacy Management.
// Copyright (C) 2023  Ian Duncan <dr8co@duck.com>
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

#pragma once

#include <openssl/evp.h>

/// \brief A class wrapper for OpenSSL cipher implementations and contexts.
class CryptoCipher {
public:
    // Only one constructor without parameters to avoid potential mix-ups
    constexpr CryptoCipher() noexcept = default;

    // Delete the copy constructor to disable copying of CryptoCipher objects
    constexpr CryptoCipher(const CryptoCipher &) noexcept = delete;

    // Delete the copy assignment operator too
    constexpr CryptoCipher &operator=(const CryptoCipher &) noexcept = delete;

    // Setters
    /// setter for the cipher implementation
    constexpr void setCipher() {
        cipher = EVP_CIPHER_fetch(libCtx, algo, propQuery);
    }

    /// Overloaded setter for cipher implementation
    constexpr void setCipher(OSSL_LIB_CTX *libraryContext, const char *algorithm, const char *propertyQuery) {
        setLibCtx(libraryContext);
        setAlgo(algorithm);
        setPropQuery(propertyQuery);

        setCipher();
    }

    /// setter for the cipher context
    void setCtx() {
        ctx = EVP_CIPHER_CTX_new();
    }

    /// setter for the library context
    constexpr void setLibCtx(OSSL_LIB_CTX *libContext) {
        libCtx = libContext;
    }

    /// setter for the cipher algorithm
    constexpr void setAlgo(const char *algorithm) {
        algo = algorithm;
    }

    /// setter for the implementation property query
    constexpr void setPropQuery(const char *propertyQuery) {
        propQuery = propertyQuery;
    }

    // Getters
    /// Getter for property query
    [[maybe_unused]] [[nodiscard]] constexpr const char *getPropQuery() const noexcept {
        return propQuery;
    }

    /// Getter for the cipher algorithm
    [[maybe_unused]] [[nodiscard]] constexpr const char *getAlgo() const noexcept {
        return algo;
    }

    /// Getter for the library context
    [[maybe_unused]] [[nodiscard]] constexpr OSSL_LIB_CTX *getLibCtx() const noexcept {
        return libCtx;
    }

    /// Getter for the cipher context
    [[nodiscard]] constexpr EVP_CIPHER_CTX *getCtx() const noexcept {
        return ctx;
    }

    /// Getter for the cipher implementation
    [[nodiscard]] constexpr EVP_CIPHER *getCipher() const noexcept {
        return cipher;
    }

    // Destructor to perform cleanup
    virtual ~CryptoCipher() {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
    }

private:
    EVP_CIPHER *cipher{nullptr};    // cipher implementation
    EVP_CIPHER_CTX *ctx{nullptr};   // cipher context
    OSSL_LIB_CTX *libCtx{nullptr};  // OpenSSL library context
    const char *algo{nullptr};      // cipher algorithm
    const char *propQuery{nullptr}; // a string to filter cipher implementations

};

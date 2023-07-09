#ifndef CRYPTO_CIPHER_CLASS
#define CRYPTO_CIPHER_CLASS

#include <openssl/evp.h>


class CryptoCipher {
public:
    // Only one constructor without parameters to avoid potential mix-ups.
    CryptoCipher() = default;

    /** Setters **/
    void setCipher();  // setter for cipher

    // Overloaded setter for cipher
    void setCipher(OSSL_LIB_CTX *libraryContext, const char *algorithm, const char *propertyQuery);

    void setCtx();                                  // setter for ctx
    void setLibCtx(OSSL_LIB_CTX *libContext);       // setter for library context
    void setAlgo(const char *algorithm);            // setter for algorithm
    void setPropQuery(const char *propertyQuery);   // setter for property query

    /** Getters **/
    // Getter for property query
    [[maybe_unused]] [[nodiscard]] const char *getPropQuery() const {
        return propQuery;
    }

    // Getter for algorithm
    [[maybe_unused]] [[nodiscard]] const char *getAlgo() const {
        return algo;
    }

    // Getter for library context
    [[maybe_unused]] [[nodiscard]] OSSL_LIB_CTX *getLibCtx() const {
        return libCtx;
    }

    // getter for ctx
    [[nodiscard]] EVP_CIPHER_CTX *getCtx() const {
        return ctx;
    }

    // getter for cipher
    [[nodiscard]] EVP_CIPHER *getCipher() const {
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

void CryptoCipher::setCtx() {
    CryptoCipher::ctx = EVP_CIPHER_CTX_new();
}

void CryptoCipher::setCipher() {
    CryptoCipher::cipher = EVP_CIPHER_fetch(CryptoCipher::libCtx, CryptoCipher::algo, CryptoCipher::propQuery);
}

void CryptoCipher::setCipher(OSSL_LIB_CTX *libraryContext, const char *algorithm, const char *propertyQuery) {
    setLibCtx(libraryContext);
    setAlgo(algorithm);
    setPropQuery(propertyQuery);

    setCipher();
}

void CryptoCipher::setLibCtx(OSSL_LIB_CTX *libContext) {
    CryptoCipher::libCtx = libContext;
}

void CryptoCipher::setAlgo(const char *algorithm) {
    CryptoCipher::algo = algorithm;
}

void CryptoCipher::setPropQuery(const char *propertyQuery) {
    CryptoCipher::propQuery = propertyQuery;
}

#endif //CRYPTO_CIPHER_CLASS

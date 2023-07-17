#ifndef CRYPTO_CIPHER_CLASS
#define CRYPTO_CIPHER_CLASS

#include <openssl/evp.h>

/**
 * @brief A RAII (Resource Acquisition Is Initialization)
 * wrapper for OpenSSL cipher implementations and contexts.
 */
class CryptoCipher {
public:

    // TODO: proper copy and move constructors

    // Only one constructor without parameters to avoid potential mix-ups.
    CryptoCipher() = default;

    // Setters
    /** setter for the cipher implementation */
    void setCipher() {
        CryptoCipher::cipher = EVP_CIPHER_fetch(CryptoCipher::libCtx, CryptoCipher::algo, CryptoCipher::propQuery);
    }

    /** Overloaded setter for cipher implementation */
    void setCipher(OSSL_LIB_CTX *libraryContext, const char *algorithm, const char *propertyQuery) {
        setLibCtx(libraryContext);
        setAlgo(algorithm);
        setPropQuery(propertyQuery);

        setCipher();
    }

    /** setter for the cipher context */
    void setCtx() {
        CryptoCipher::ctx = EVP_CIPHER_CTX_new();
    }

    /** setter for the library context */
    void setLibCtx(OSSL_LIB_CTX *libContext) {
        CryptoCipher::libCtx = libContext;
    }

    /** setter for the cipher algorithm */
    void setAlgo(const char *algorithm) {
        CryptoCipher::algo = algorithm;
    }

    /** setter for the implementation property query */
    void setPropQuery(const char *propertyQuery) {
        CryptoCipher::propQuery = propertyQuery;
    }

    // Getters
    /** Getter for property query */
    [[maybe_unused]] [[nodiscard]] const char *getPropQuery() const {
        return propQuery;
    }

    /** Getter for the cipher algorithm */
    [[maybe_unused]] [[nodiscard]] const char *getAlgo() const {
        return algo;
    }

    /** Getter for the library context */
    [[maybe_unused]] [[nodiscard]] OSSL_LIB_CTX *getLibCtx() const {
        return libCtx;
    }

    /** Getter for the cipher context */
    [[nodiscard]] EVP_CIPHER_CTX *getCtx() const {
        return ctx;
    }

    /** Getter for the cipher implementation */
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

#endif //CRYPTO_CIPHER_CLASS

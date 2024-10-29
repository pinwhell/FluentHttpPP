#pragma once

#include <memory>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#define DEFINE_OPENSSL_DELETER_TRAIT(type) \
template<> \
struct OpenSSLDeleterTrait<type> { \
    static void free(type* obj) { \
        type##_free(obj); \
    } \
};

template<typename T>
struct OpenSSLDeleterTrait;

DEFINE_OPENSSL_DELETER_TRAIT(RSA)
DEFINE_OPENSSL_DELETER_TRAIT(EVP_PKEY)
DEFINE_OPENSSL_DELETER_TRAIT(EVP_MD_CTX)
DEFINE_OPENSSL_DELETER_TRAIT(EVP_CIPHER_CTX)
DEFINE_OPENSSL_DELETER_TRAIT(BIO)

template<typename T>
struct OpenSSLDeleter {
    inline void operator()(T* obj) const {
        if (obj) {
            OpenSSLDeleterTrait<T>::free(obj);
        }
    }
};

namespace std {
    template<typename T>
    using openssl_uptr = std::unique_ptr<T, OpenSSLDeleter<T>>;
}
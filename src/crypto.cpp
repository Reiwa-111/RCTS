#include "crypto.hpp"

#include "format.hpp"

#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstdlib>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace rcts::crypto {
namespace {
constexpr char kHkdfInfoV0_1[] = "RCTS v0.1 AES-256-GCM container key";
constexpr char kHkdfInfoV0_3[] = "RCTS v0.3 AES-256-GCM container key";

[[noreturn]] void fail(const char* message) {
    throw std::runtime_error(message);
}

#ifdef RCTS_ENABLE_FAULT_INJECTION
void inject_fault(const char* point) {
    const char* requested = std::getenv("RCTS_FAULT");
    if (requested != nullptr && std::string_view(requested) == point) {
        throw std::runtime_error(std::string("Injected fault: ") + point);
    }
}
#else
void inject_fault(const char*) {}
#endif

class CleanseGuard {
public:
    CleanseGuard(void* memory, std::size_t size) noexcept : memory_(memory), size_(size) {}
    CleanseGuard(const CleanseGuard&) = delete;
    CleanseGuard& operator=(const CleanseGuard&) = delete;
    void release() noexcept { memory_ = nullptr; size_ = 0; }
    ~CleanseGuard() {
        if (memory_ != nullptr && size_ != 0) OPENSSL_cleanse(memory_, size_);
    }
private:
    void* memory_;
    std::size_t size_;
};
} // namespace

void random_bytes(unsigned char* destination, std::size_t size) {
#ifdef RCTS_ENABLE_KAT
    // Test-only deterministic entropy for the encryption known-answer target.
    if (size == format::kSaltSize) {
        for (std::size_t i = 0; i < size; ++i)
            destination[i] = static_cast<unsigned char>(i);
        return;
    }
    if (size == format::kNoncePrefixSize) {
        for (std::size_t i = 0; i < size; ++i)
            destination[i] = static_cast<unsigned char>(0xA0U + i);
        return;
    }
#endif
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        RAND_bytes(destination, static_cast<int>(size)) != 1) {
        fail("OpenSSL secure random generator failed");
    }
}

void derive_file_key(const std::array<unsigned char, 32>& master,
                    const unsigned char* salt,
                    std::array<unsigned char, 32>& result,
                    unsigned char container_version) {
    const char* info = nullptr;
    std::size_t info_size = 0;
    if (container_version == format::kLegacyVersion) {
        info = kHkdfInfoV0_1;
        info_size = sizeof(kHkdfInfoV0_1) - 1;
    } else if (container_version == format::kVersion) {
        info = kHkdfInfoV0_3;
        info_size = sizeof(kHkdfInfoV0_3) - 1;
    } else {
        fail("Unsupported container version for key derivation");
    }
    EVP_KDF* raw_kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (raw_kdf == nullptr) fail("OpenSSL HKDF is unavailable");
    const auto free_kdf = [](EVP_KDF* value) { EVP_KDF_free(value); };
    std::unique_ptr<EVP_KDF, decltype(free_kdf)> kdf(raw_kdf, free_kdf);

    EVP_KDF_CTX* raw_ctx = EVP_KDF_CTX_new(kdf.get());
    if (raw_ctx == nullptr) fail("Cannot allocate HKDF context");
    const auto free_ctx = [](EVP_KDF_CTX* value) { EVP_KDF_CTX_free(value); };
    std::unique_ptr<EVP_KDF_CTX, decltype(free_ctx)> ctx(raw_ctx, free_ctx);

    std::array<unsigned char, format::kSaltSize> salt_input{};
    CleanseGuard salt_guard(salt_input.data(), salt_input.size());
    std::copy_n(salt, salt_input.size(), salt_input.begin());
    char digest[] = "SHA256";
    int hkdf_mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &hkdf_mode),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                        const_cast<unsigned char*>(master.data()),
                                        master.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt_input.data(), salt_input.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                        const_cast<char*>(info), info_size),
        OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_derive(ctx.get(), result.data(), result.size(), parameters) <= 0) {
        fail("HKDF-SHA-256 derivation failed");
    }
}

std::vector<unsigned char> encrypt_gcm(
    const std::array<unsigned char, 32>& key,
    const std::array<unsigned char, 12>& nonce,
    const std::vector<unsigned char>& aad,
    const unsigned char* plaintext, std::size_t plaintext_size) {
    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
    if (raw == nullptr) fail("Cannot allocate AES-GCM context");
    const auto cleanup = [](EVP_CIPHER_CTX* ctx) { EVP_CIPHER_CTX_free(ctx); };
    std::unique_ptr<EVP_CIPHER_CTX, decltype(cleanup)> ctx(raw, cleanup);

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        fail("AES-256-GCM initialization failed");
    }
    int produced = 0;
    if (EVP_EncryptUpdate(ctx.get(), nullptr, &produced, aad.data(),
                          static_cast<int>(aad.size())) != 1) {
        fail("AES-GCM AAD processing failed");
    }
    std::vector<unsigned char> ciphertext(plaintext_size + format::kTagSize);
    int total = 0;
    if (plaintext_size > 0) {
        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &produced, plaintext,
                             static_cast<int>(plaintext_size)) != 1) {
            fail("AES-GCM encryption failed");
        }
        total += produced;
    }
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + total, &produced) != 1) {
        fail("AES-GCM finalization failed");
    }
    total += produced;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(format::kTagSize), ciphertext.data() + total) != 1) {
        fail("AES-GCM tag extraction failed");
    }
    ciphertext.resize(static_cast<std::size_t>(total) + format::kTagSize);
    return ciphertext;
}

bool decrypt_gcm(const std::array<unsigned char, 32>& key,
                const std::array<unsigned char, 12>& nonce,
                const std::vector<unsigned char>& aad,
                const std::vector<unsigned char>& ciphertext_and_tag,
                std::vector<unsigned char>& plaintext) {
    // Treat output as owned secret state: callers may reuse a vector from a
    // previous successful decrypt. Clear the old bytes before any early return
    // or allocation that could replace its storage.
    if (!plaintext.empty()) OPENSSL_cleanse(plaintext.data(), plaintext.size());
    plaintext.clear();
    if (ciphertext_and_tag.size() < format::kTagSize) return false;
    const std::size_t ciphertext_size = ciphertext_and_tag.size() - format::kTagSize;
    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
    if (raw == nullptr) fail("Cannot allocate AES-GCM context");
    const auto cleanup = [](EVP_CIPHER_CTX* ctx) { EVP_CIPHER_CTX_free(ctx); };
    std::unique_ptr<EVP_CIPHER_CTX, decltype(cleanup)> ctx(raw, cleanup);

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        fail("AES-256-GCM initialization failed");
    }
    int produced = 0;
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &produced, aad.data(),
                          static_cast<int>(aad.size())) != 1) {
        fail("AES-GCM AAD processing failed");
    }

    plaintext.assign(ciphertext_size + format::kTagSize, 0);
    CleanseGuard plaintext_guard(plaintext.data(), plaintext.size());
    int total = 0;
    if (ciphertext_size > 0) {
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &produced,
                              ciphertext_and_tag.data(),
                              static_cast<int>(ciphertext_size)) != 1) {
            OPENSSL_cleanse(plaintext.data(), plaintext.size());
            plaintext.clear();
            return false;
        }
        total += produced;
    }
    std::array<unsigned char, format::kTagSize> tag{};
    CleanseGuard tag_guard(tag.data(), tag.size());
    std::copy_n(ciphertext_and_tag.data() + ciphertext_size, format::kTagSize, tag.begin());
    inject_fault("decrypt-tag-setup");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(format::kTagSize), tag.data()) != 1) {
        fail("AES-GCM tag setup failed");
    }
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total, &produced) != 1) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        plaintext.clear();
        return false;
    }
    total += produced;
    plaintext.resize(static_cast<std::size_t>(total));
    plaintext_guard.release();
    return true;
}

} // namespace rcts::crypto

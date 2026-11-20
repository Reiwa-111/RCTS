#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#ifndef RCTS_VERSION
#define RCTS_VERSION "0.3.0"
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>

#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1U
#endif
#endif

namespace fs = std::filesystem;
using Bytes = std::vector<unsigned char>;

namespace {
constexpr std::array<unsigned char, 8> kMagic{
    'R', 'C', 'T', 'S', '\r', '\n', 0x1A, '\n'};
constexpr unsigned char kVersion = 1;
// FORMAT v0.1 cryptographic constants are frozen. Do not change these values
// without defining a new container format version and migration path.
constexpr char kHkdfInfoV0_1[] = "RCTS v0.1 AES-256-GCM container key";
constexpr std::uint32_t kChunkSize = 1024U * 1024U;
constexpr std::size_t kSaltSize = 16;
constexpr std::size_t kNoncePrefixSize = 4;
constexpr std::size_t kTagSize = 16;
constexpr std::size_t kHeaderSize = 8 + 1 + 4 + kSaltSize + kNoncePrefixSize;
constexpr std::size_t kRecordHeaderSize = 5;
constexpr unsigned char kFinalRecord = 1;
constexpr std::uint32_t kMaxRecords = 1U << 16; // 64 GiB maximum at 1 MiB per record.
constexpr std::uint64_t kMaxPlaintextSize =
    static_cast<std::uint64_t>(kMaxRecords) * kChunkSize;

[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error(message);
}

class CleanseGuard {
public:
    CleanseGuard(void* memory, std::size_t size) : memory_(memory), size_(size) {}
    CleanseGuard(const CleanseGuard&) = delete;
    CleanseGuard& operator=(const CleanseGuard&) = delete;
    ~CleanseGuard() {
        if (memory_ != nullptr && size_ != 0) OPENSSL_cleanse(memory_, size_);
    }
private:
    void* memory_;
    std::size_t size_;
};

// Filesystem paths are converted to UTF-8 for messages so that diagnostics do
// not depend on the active Windows ANSI code page.
std::string display_path(const fs::path& path) {
    const std::u8string encoded = path.u8string();
    return std::string(reinterpret_cast<const char*>(encoded.data()), encoded.size());
}

std::string errno_message(int value) {
    if (value == 0) return "unknown error (errno 0)";
    return std::generic_category().message(value);
}

#ifdef _WIN32
std::string win32_message(unsigned long value) {
    if (value == 0) return "unknown error (GetLastError 0)";
    return std::system_category().message(static_cast<int>(value)) +
           " (Win32 error " + std::to_string(value) + ")";
}
#endif

void random_bytes(unsigned char* destination, std::size_t size) {
#ifdef RCTS_ENABLE_KAT
    // Test-only deterministic entropy for the encryption known-answer target.
    if (size == kSaltSize) {
        for (std::size_t i = 0; i < size; ++i) destination[i] = static_cast<unsigned char>(i);
        return;
    }
    if (size == kNoncePrefixSize) {
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

// symlink_status() reports dangling symlinks as existing entries, unlike exists().
bool path_entry_exists(const fs::path& path) {
    std::error_code error;
    const fs::file_status status = fs::symlink_status(path, error);
    if (error) {
        if (error == std::errc::no_such_file_or_directory ||
            error == std::errc::not_a_directory) {
            return false;
        }
        fail("Cannot inspect path '" + display_path(path) + "': " + error.message());
    }
    return status.type() != fs::file_type::not_found;
}

void put_u32(unsigned char* destination, std::uint32_t value) {
    destination[0] = static_cast<unsigned char>(value >> 24U);
    destination[1] = static_cast<unsigned char>(value >> 16U);
    destination[2] = static_cast<unsigned char>(value >> 8U);
    destination[3] = static_cast<unsigned char>(value);
}

void put_u64(unsigned char* destination, std::uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        destination[i] = static_cast<unsigned char>(value);
        value >>= 8U;
    }
}

std::uint32_t get_u32(const unsigned char* source) {
    return (static_cast<std::uint32_t>(source[0]) << 24U) |
           (static_cast<std::uint32_t>(source[1]) << 16U) |
           (static_cast<std::uint32_t>(source[2]) << 8U) |
           static_cast<std::uint32_t>(source[3]);
}

#ifdef RCTS_ENABLE_FAULT_INJECTION
// Test-only hook. It is compiled in only when the CMake option
// RCTS_ENABLE_FAULT_INJECTION is enabled; release builds contain no such path.
void inject_fault(const char* point) {
    const char* requested = std::getenv("RCTS_FAULT");
    if (requested != nullptr && std::string_view(requested) == point) {
        fail(std::string("Injected fault: ") + point);
    }
}
#else
void inject_fault(const char*) {}
#endif

void close_descriptor_noexcept(int descriptor) noexcept {
    if (descriptor < 0) return;
#ifdef _WIN32
    _close(descriptor);
#else
    ::close(descriptor);
#endif
}

void close_descriptor(int descriptor, const fs::path& path) {
#ifdef _WIN32
    if (_close(descriptor) != 0) {
        fail("Failed to close output file '" + display_path(path) + "': " +
             errno_message(errno));
    }
#else
    // POSIX leaves the descriptor state unspecified after EINTR. On Linux the
    // descriptor is closed, and retrying could close an unrelated descriptor.
    const int result = ::close(descriptor);
    if (result != 0 && errno != EINTR) {
        fail("Failed to close output file '" + display_path(path) + "': " +
             errno_message(errno));
    }
#endif
}

std::size_t read_some(int descriptor, void* buffer, std::size_t size,
                      const fs::path& path) {
    if (size == 0) return 0;
#ifdef _WIN32
    const auto request = static_cast<unsigned int>(
        std::min<std::size_t>(size, std::numeric_limits<unsigned int>::max()));
    const int count = _read(descriptor, buffer, request);
#else
    ssize_t count = 0;
    do {
        count = ::read(descriptor, buffer, size);
    } while (count < 0 && errno == EINTR);
#endif
    if (count < 0) {
        fail("Failed to read '" + display_path(path) + "': " + errno_message(errno));
    }
    return static_cast<std::size_t>(count);
}

void write_all(int descriptor, const void* data, std::size_t size,
               const fs::path& path) {
    const auto* bytes = static_cast<const unsigned char*>(data);
    while (size > 0) {
        const std::size_t request = std::min<std::size_t>(
            size, static_cast<std::size_t>(std::numeric_limits<unsigned int>::max()));
#ifdef _WIN32
        const int written = _write(descriptor, bytes, static_cast<unsigned int>(request));
#else
        ssize_t written = 0;
        do {
            written = ::write(descriptor, bytes, request);
        } while (written < 0 && errno == EINTR);
#endif
        if (written <= 0) {
            fail("Failed to write output file '" + display_path(path) + "': " +
                 errno_message(written == 0 ? 0 : errno));
        }
        const auto amount = static_cast<std::size_t>(written);
        bytes += amount;
        size -= amount;
    }
}

int open_read_only(const fs::path& path, const char* description) {
#ifdef _WIN32
    const int descriptor =
        _wopen(path.c_str(), _O_RDONLY | _O_BINARY | _O_NOINHERIT);
#else
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NONBLOCK
    // Avoid blocking forever when a non-regular file (for example a FIFO) is
    // passed by mistake; the descriptor is rejected immediately afterwards.
    flags |= O_NONBLOCK;
#endif
    int descriptor = -1;
    do {
        descriptor = ::open(path.c_str(), flags);
    } while (descriptor < 0 && errno == EINTR);
#endif
    if (descriptor < 0) {
        fail("Cannot open " + std::string(description) + " '" + display_path(path) +
             "': " + errno_message(errno));
    }
    return descriptor;
}

// Opens an input file and validates the already-open descriptor, so the check
// cannot be bypassed by replacing the path between the check and the open.
class InputFile {
public:
    InputFile(const fs::path& path, const char* description) : path_(path) {
        std::error_code status_error;
        if (!fs::is_regular_file(path, status_error)) {
            if (status_error == std::errc::no_such_file_or_directory) {
                fail(std::string(description) + " does not exist: " + display_path(path));
            }
            if (status_error) {
                fail("Cannot inspect " + std::string(description) + " '" +
                     display_path(path) + "': " + status_error.message());
            }
            fail(std::string(description) + " is not a regular file: " +
                 display_path(path));
        }

        descriptor_ = open_read_only(path, description);
        try {
            validate_descriptor(description);
        } catch (...) {
            close_descriptor_noexcept(descriptor_);
            descriptor_ = -1;
            throw;
        }
    }

    InputFile(const InputFile&) = delete;
    InputFile& operator=(const InputFile&) = delete;

    ~InputFile() { close_descriptor_noexcept(descriptor_); }

    std::uint64_t size() const { return size_; }

    // Fills up to `size` bytes; returns fewer only at end of file.
    std::size_t read(unsigned char* buffer, std::size_t size) {
        std::size_t total = 0;
        while (total < size) {
            const std::size_t count =
                read_some(descriptor_, buffer + total, size - total, path_);
            if (count == 0) break;
            total += count;
        }
        return total;
    }

    void read_exact(unsigned char* buffer, std::size_t size, const char* what) {
        std::size_t total = 0;
        while (total < size) {
            const std::size_t count =
                read_some(descriptor_, buffer + total, size - total, path_);
            if (count == 0) {
                fail(std::string("Truncated container while reading ") + what);
            }
            total += count;
        }
    }

    bool has_more_data() {
        unsigned char byte = 0;
        return read_some(descriptor_, &byte, 1, path_) == 1;
    }

private:
    void validate_descriptor(const char* description) {
#ifdef _WIN32
        struct _stat64 info {};
        if (_fstat64(descriptor_, &info) != 0) {
            fail("Cannot inspect " + std::string(description) + " '" +
                 display_path(path_) + "': " + errno_message(errno));
        }
        if ((info.st_mode & _S_IFMT) != _S_IFREG) {
            fail(std::string(description) + " is not a regular file: " +
                 display_path(path_));
        }
        size_ = static_cast<std::uint64_t>(info.st_size);
#else
        struct stat info {};
        if (fstat(descriptor_, &info) != 0) {
            fail("Cannot inspect " + std::string(description) + " '" +
                 display_path(path_) + "': " + errno_message(errno));
        }
        if (!S_ISREG(info.st_mode)) {
            fail(std::string(description) + " is not a regular file: " +
                 display_path(path_));
        }
        size_ = static_cast<std::uint64_t>(info.st_size);
#endif
    }

    fs::path path_;
    int descriptor_ = -1;
    std::uint64_t size_ = 0;
};

std::string key_bytes_to_unicode(const std::array<unsigned char, 32>& key) {
    // U+4E00..U+4EFF is a fixed 256-code-point alphabet: one code point per key byte.
    std::string encoded;
    encoded.reserve(96);
    for (const unsigned char byte : key) {
        const unsigned int value = 0x4E00U + byte;
        encoded.push_back(static_cast<char>(0xE4));
        encoded.push_back(static_cast<char>(0xB8U + ((value - 0x4E00U) >> 6U)));
        encoded.push_back(static_cast<char>(0x80U + ((value - 0x4E00U) & 0x3FU)));
    }
    return encoded;
}

std::array<unsigned char, 32> unicode_to_key_bytes(const fs::path& path) {
    InputFile input(path, "Key file");

    // The valid form is at most 96 UTF-8 bytes plus one CRLF. Read a bounded
    // prefix so a wrong path cannot force an unbounded allocation.
    if (input.size() >= 1024) {
        fail("Invalid key: key file is too large");
    }
    std::array<char, 1024> buffer{};
    CleanseGuard buffer_guard(buffer.data(), buffer.size());
    const std::size_t count = input.read(
        reinterpret_cast<unsigned char*>(buffer.data()), buffer.size());
    std::string encoded(buffer.data(), count);

    if (!encoded.empty() && encoded.ends_with("\r\n")) encoded.resize(encoded.size() - 2);
    else if (!encoded.empty() && encoded.back() == '\n') encoded.pop_back();
    CleanseGuard encoded_guard(encoded.data(), encoded.size());

    if (encoded.size() != 96) {
        fail("Invalid key: expected exactly 32 Unicode code points from U+4E00..U+4EFF");
    }

    std::array<unsigned char, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        const auto b0 = static_cast<unsigned char>(encoded[i * 3]);
        const auto b1 = static_cast<unsigned char>(encoded[i * 3 + 1]);
        const auto b2 = static_cast<unsigned char>(encoded[i * 3 + 2]);
        if (b0 != 0xE4 || b1 < 0xB8 || b1 > 0xBB || b2 < 0x80 || b2 > 0xBF) {
            fail("Invalid key: unsupported Unicode character or malformed UTF-8");
        }
        const unsigned int offset =
            (static_cast<unsigned int>(b1 - 0xB8) << 6U) |
            static_cast<unsigned int>(b2 - 0x80);
        key[i] = static_cast<unsigned char>(offset);
    }
    return key;
}

std::array<unsigned char, 32> derive_file_key(
    const std::array<unsigned char, 32>& master,
    const unsigned char* salt) {
    EVP_KDF* raw_kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (raw_kdf == nullptr) fail("OpenSSL HKDF is unavailable");
    const auto free_kdf = [](EVP_KDF* value) { EVP_KDF_free(value); };
    std::unique_ptr<EVP_KDF, decltype(free_kdf)> kdf(raw_kdf, free_kdf);

    EVP_KDF_CTX* raw_ctx = EVP_KDF_CTX_new(kdf.get());
    if (raw_ctx == nullptr) fail("Cannot allocate HKDF context");
    const auto free_ctx = [](EVP_KDF_CTX* value) { EVP_KDF_CTX_free(value); };
    std::unique_ptr<EVP_KDF_CTX, decltype(free_ctx)> ctx(raw_ctx, free_ctx);

    auto key_input = master;
    CleanseGuard key_input_guard(key_input.data(), key_input.size());
    std::array<unsigned char, kSaltSize> salt_input{};
    std::copy_n(salt, salt_input.size(), salt_input.begin());
    char digest[] = "SHA256";
    int hkdf_mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &hkdf_mode),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key_input.data(), key_input.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt_input.data(), salt_input.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                        const_cast<char*>(kHkdfInfoV0_1),
                                        sizeof(kHkdfInfoV0_1) - 1),
        OSSL_PARAM_construct_end()
    };

    std::array<unsigned char, 32> result{};
    if (EVP_KDF_derive(ctx.get(), result.data(), result.size(), parameters) <= 0) {
        fail("HKDF-SHA-256 derivation failed");
    }
    return result;
}

std::array<unsigned char, 12> make_nonce(const unsigned char* prefix,
                                         std::uint64_t index) {
    std::array<unsigned char, 12> nonce{};
    std::copy_n(prefix, kNoncePrefixSize, nonce.begin());
    put_u64(nonce.data() + kNoncePrefixSize, index);
    return nonce;
}

Bytes make_aad(const std::array<unsigned char, kHeaderSize>& header,
               std::uint64_t index, std::uint32_t plaintext_size,
               unsigned char flags) {
    Bytes aad(header.begin(), header.end());
    const std::size_t old_size = aad.size();
    aad.resize(old_size + 8 + 4 + 1);
    put_u64(aad.data() + old_size, index);
    put_u32(aad.data() + old_size + 8, plaintext_size);
    aad[old_size + 12] = flags;
    return aad;
}

Bytes encrypt_gcm(const std::array<unsigned char, 32>& key,
                  const std::array<unsigned char, 12>& nonce,
                  const Bytes& aad, const unsigned char* plaintext,
                  std::size_t plaintext_size) {
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

    Bytes ciphertext(plaintext_size + kTagSize);
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
                            static_cast<int>(kTagSize), ciphertext.data() + total) != 1) {
        fail("AES-GCM tag extraction failed");
    }
    ciphertext.resize(static_cast<std::size_t>(total) + kTagSize);
    return ciphertext;
}

bool decrypt_gcm(const std::array<unsigned char, 32>& key,
                 const std::array<unsigned char, 12>& nonce,
                 const Bytes& aad, const Bytes& ciphertext_and_tag,
                 Bytes& plaintext) {
    if (ciphertext_and_tag.size() < kTagSize) return false;
    const std::size_t ciphertext_size = ciphertext_and_tag.size() - kTagSize;
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

    plaintext.assign(ciphertext_size + 16, 0);
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

    std::array<unsigned char, kTagSize> tag{};
    std::copy_n(ciphertext_and_tag.data() + ciphertext_size, kTagSize, tag.begin());
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(kTagSize), tag.data()) != 1) {
        fail("AES-GCM tag setup failed");
    }
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total, &produced) != 1) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        plaintext.clear();
        return false;
    }
    total += produced;
    plaintext.resize(static_cast<std::size_t>(total));
    return true;
}

fs::path make_temp_path(const fs::path& destination) {
    std::array<unsigned char, 16> random{};
    random_bytes(random.data(), random.size());
    static constexpr char hex[] = "0123456789abcdef";
    std::string name = ".rcts.partial-";
    for (const auto byte : random) {
        name.push_back(hex[byte >> 4U]);
        name.push_back(hex[byte & 0x0FU]);
    }
    // Keep the temporary file next to the destination, but do not append to
    // the destination name: long valid names must not fail only because of
    // the temporary suffix, and the temporary name should not disclose it.
    fs::path directory = destination.parent_path();
    if (directory.empty()) directory = ".";
    return directory / name;
}

#ifdef _WIN32
namespace win32 {

struct Handle {
    HANDLE value = nullptr;

    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() {
        if (value != nullptr && value != INVALID_HANDLE_VALUE) CloseHandle(value);
    }
};

struct LocalString {
    LPWSTR value = nullptr;

    LocalString() = default;
    LocalString(const LocalString&) = delete;
    LocalString& operator=(const LocalString&) = delete;
    ~LocalString() {
        if (value != nullptr) LocalFree(value);
    }
};

struct LocalDescriptor {
    PSECURITY_DESCRIPTOR value = nullptr;

    LocalDescriptor() = default;
    LocalDescriptor(const LocalDescriptor&) = delete;
    LocalDescriptor& operator=(const LocalDescriptor&) = delete;
    LocalDescriptor(LocalDescriptor&& other) noexcept
        : value(std::exchange(other.value, nullptr)) {}
    LocalDescriptor& operator=(LocalDescriptor&&) = delete;
    ~LocalDescriptor() {
        if (value != nullptr) LocalFree(value);
    }
};

// A protected DACL that grants full access only to the current user, SYSTEM
// and the local Administrators group. SE_DACL_PROTECTED prevents inherited
// entries from widening access.
LocalDescriptor make_private_security_descriptor() {
    Handle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) {
        fail("Cannot open process token: " + win32_message(GetLastError()));
    }

    DWORD required = 0;
    if (!GetTokenInformation(token.value, TokenUser, nullptr, 0, &required) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        fail("Cannot query token user: " + win32_message(GetLastError()));
    }
    if (required == 0) fail("Cannot query token user: empty result");

    std::vector<unsigned char> user_buffer(required);
    if (!GetTokenInformation(token.value, TokenUser, user_buffer.data(), required,
                             &required)) {
        fail("Cannot query token user: " + win32_message(GetLastError()));
    }
    const PSID user_sid =
        reinterpret_cast<const TOKEN_USER*>(user_buffer.data())->User.Sid;

    LocalString user_sid_text;
    if (!ConvertSidToStringSidW(user_sid, &user_sid_text.value)) {
        fail("Cannot convert user SID: " + win32_message(GetLastError()));
    }

    std::wstring sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;";
    sddl += user_sid_text.value;
    sddl += L")";

    LocalDescriptor descriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor.value, nullptr)) {
        fail("Cannot build private security descriptor: " +
             win32_message(GetLastError()));
    }
    return descriptor;
}

} // namespace win32
#endif

int create_exclusive_writable_file(const fs::path& path) {
#ifdef _WIN32
    auto security = win32::make_private_security_descriptor();
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = security.value;
    attributes.bInheritHandle = FALSE;

    const HANDLE handle = CreateFileW(
        path.c_str(), GENERIC_WRITE, 0, &attributes, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS) {
            fail("Refusing to overwrite existing output: " + display_path(path));
        }
        fail("Cannot create output file '" + display_path(path) + "': " +
             win32_message(error));
    }

    const int file_descriptor = _open_osfhandle(
        reinterpret_cast<intptr_t>(handle), _O_WRONLY | _O_BINARY);
    if (file_descriptor < 0) {
        const int error = errno;
        CloseHandle(handle);
        DeleteFileW(path.c_str());
        fail("Cannot wrap output file handle '" + display_path(path) + "': " +
             errno_message(error));
    }
    return file_descriptor;
#else
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int descriptor = -1;
    do {
        descriptor = ::open(path.c_str(), flags, 0600);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0) {
        fail("Cannot create output file '" + display_path(path) + "': " +
             errno_message(errno));
    }
    return descriptor;
#endif
}

void sync_output_file(int descriptor, const fs::path& path) {
#ifdef _WIN32
    if (_commit(descriptor) != 0) {
        fail("Failed to sync output file '" + display_path(path) + "': " +
             errno_message(errno));
    }
#else
    int result = 0;
    do {
        result = ::fsync(descriptor);
    } while (result != 0 && errno == EINTR);
    if (result != 0) {
        fail("Failed to sync output file '" + display_path(path) + "': " +
             errno_message(errno));
    }
#endif
}

void publish_no_clobber(const fs::path& temp, const fs::path& destination) {
#ifdef _WIN32
    // A plain MoveFileExW fails when the destination exists; MOVEFILE_REPLACE
    // must never be added here. MOVEFILE_WRITE_THROUGH flushes metadata.
    if (MoveFileExW(temp.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH)) {
        return;
    }
    const DWORD rename_error = GetLastError();
    if (rename_error == ERROR_FILE_EXISTS || rename_error == ERROR_ALREADY_EXISTS) {
        fail("Refusing to overwrite existing output: " + display_path(destination));
    }

    // Fallback for filesystems where MoveFileExW cannot rename within a volume.
    if (CreateHardLinkW(destination.c_str(), temp.c_str(), nullptr)) {
        if (!DeleteFileW(temp.c_str())) {
            std::cerr << "warning: output was committed, but temporary alias remains: "
                      << display_path(temp) << "\r\n";
        }
        return;
    }
    const DWORD link_error = GetLastError();
    if (link_error == ERROR_FILE_EXISTS || link_error == ERROR_ALREADY_EXISTS) {
        fail("Refusing to overwrite existing output: " + display_path(destination));
    }
    fail("Cannot publish output without overwriting (rename: " +
         win32_message(rename_error) + "; hard-link fallback: " +
         win32_message(link_error) + ")");
#else
#if defined(__linux__) && defined(_GNU_SOURCE)
    {
        int status = 0;
        do {
            status = ::renameat2(AT_FDCWD, temp.c_str(), AT_FDCWD,
                                 destination.c_str(), RENAME_NOREPLACE);
        } while (status != 0 && errno == EINTR);
        if (status == 0) return;
        if (errno == EEXIST) {
            fail("Refusing to overwrite existing output: " +
                 display_path(destination));
        }
        const int error = errno;
        if (error != ENOSYS && error != EINVAL && error != EOPNOTSUPP) {
            fail("Cannot publish output without overwriting: " + errno_message(error));
        }
    }
#endif
    int link_status = 0;
    do {
        link_status = ::link(temp.c_str(), destination.c_str());
    } while (link_status != 0 && errno == EINTR);
    if (link_status != 0) {
        if (errno == EEXIST) {
            fail("Refusing to overwrite existing output: " +
                 display_path(destination));
        }
        fail("Cannot publish output without overwriting: " + errno_message(errno));
    }

    int unlink_status = 0;
    do {
        unlink_status = ::unlink(temp.c_str());
    } while (unlink_status != 0 && errno == EINTR);
    if (unlink_status != 0) {
        std::cerr << "warning: output was committed, but temporary alias remains: "
                      << display_path(temp) << "\r\n";
    }
#endif
}

// Best effort: make the new directory entry durable on POSIX. Failure here is
// not fatal because the file data itself has already been synced.
void sync_parent_directory(const fs::path& destination) noexcept {
#ifndef _WIN32
    try {
        fs::path directory = destination.parent_path();
        if (directory.empty()) directory = ".";
        int flags = O_RDONLY;
#ifdef O_DIRECTORY
        flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
        int descriptor = -1;
        do {
            descriptor = ::open(directory.c_str(), flags);
        } while (descriptor < 0 && errno == EINTR);
        if (descriptor < 0) return;
        while (::fsync(descriptor) != 0 && errno == EINTR) {
        }
        ::close(descriptor);
    } catch (...) {
        // Best effort only.
    }
#else
    (void)destination;
#endif
}

// Writes to a uniquely named sibling file and publishes it with a no-clobber
// rename/link only after the complete result has been synced and closed.
class AtomicOutput {
public:
    explicit AtomicOutput(const fs::path& destination)
        : destination_(destination), temp_path_(make_temp_path(destination)) {
        inject_fault("create");
        descriptor_ = create_exclusive_writable_file(temp_path_);
    }

    AtomicOutput(const AtomicOutput&) = delete;
    AtomicOutput& operator=(const AtomicOutput&) = delete;

    ~AtomicOutput() {
        close_noexcept();
        if (!committed_) {
            std::error_code ignored;
            fs::remove(temp_path_, ignored);
        }
    }

    void write(const void* data, std::size_t size) {
        if (size == 0) return;
        if (descriptor_ < 0) fail("Output file is already closed");
        inject_fault("write");
        write_all(descriptor_, data, size, temp_path_);
    }

    void commit() {
        if (descriptor_ < 0) fail("Output file is already closed");
        inject_fault("sync");
        sync_output_file(descriptor_, temp_path_);
        inject_fault("close");
        close_checked();
        inject_fault("publish");
        publish_no_clobber(temp_path_, destination_);
        sync_parent_directory(destination_);
        committed_ = true;
    }

private:
    void close_checked() {
        if (descriptor_ < 0) return;
        const int descriptor = descriptor_;
        descriptor_ = -1;
        close_descriptor(descriptor, temp_path_);
    }

    void close_noexcept() {
        if (descriptor_ < 0) return;
        const int descriptor = descriptor_;
        descriptor_ = -1;
        close_descriptor_noexcept(descriptor);
    }

    fs::path destination_;
    fs::path temp_path_;
    int descriptor_ = -1;
    bool committed_ = false;
};

void write_exact(AtomicOutput& output, const unsigned char* source, std::size_t size) {
    output.write(source, size);
}

std::size_t read_chunk(InputFile& input, Bytes& buffer) {
    return input.read(buffer.data(), buffer.size());
}

void write_record(AtomicOutput& output,
                  const std::array<unsigned char, kHeaderSize>& header,
                  const std::array<unsigned char, 32>& file_key,
                  std::uint64_t index, const unsigned char* data,
                  std::uint32_t size, unsigned char flags) {
    std::array<unsigned char, kRecordHeaderSize> record_header{};
    put_u32(record_header.data(), size);
    record_header[4] = flags;
    const auto nonce = make_nonce(header.data() + 29, index);
    const auto aad = make_aad(header, index, size, flags);
    const Bytes encrypted = encrypt_gcm(file_key, nonce, aad, data, size);
    write_exact(output, record_header.data(), record_header.size());
    write_exact(output, encrypted.data(), encrypted.size());
}

void encrypt_file(const fs::path& key_path, const fs::path& input_path,
                  const fs::path& output_path) {
    if (path_entry_exists(output_path)) {
        fail("Refusing to overwrite existing output: " + display_path(output_path));
    }
    InputFile input(input_path, "Input file");
    if (input.size() > kMaxPlaintextSize) {
        fail("Container exceeds the v0.1 record limit");
    }
    auto master_key = unicode_to_key_bytes(key_path);
    CleanseGuard master_key_guard(master_key.data(), master_key.size());

    std::array<unsigned char, kHeaderSize> header{};
    std::copy(kMagic.begin(), kMagic.end(), header.begin());
    header[8] = kVersion;
    put_u32(header.data() + 9, kChunkSize);
    random_bytes(header.data() + 13, kSaltSize);
    random_bytes(header.data() + 29, kNoncePrefixSize);
    auto file_key = derive_file_key(master_key, header.data() + 13);
    CleanseGuard file_key_guard(file_key.data(), file_key.size());

    AtomicOutput output(output_path);
    write_exact(output, header.data(), header.size());

    Bytes current(kChunkSize), next(kChunkSize);
    CleanseGuard current_guard(current.data(), current.size());
    CleanseGuard next_guard(next.data(), next.size());
    std::size_t current_size = read_chunk(input, current);
    std::uint64_t index = 0;
    if (current_size == 0) {
        write_record(output, header, file_key, index, current.data(), 0, kFinalRecord);
    } else {
        while (true) {
            const std::size_t next_size = read_chunk(input, next);
            const bool final = next_size == 0;
            if (index >= kMaxRecords) fail("Container exceeds the v0.1 record limit");
            write_record(output, header, file_key, index, current.data(),
                         static_cast<std::uint32_t>(current_size),
                         final ? kFinalRecord : 0);
            ++index;
            if (final) break;
            current.swap(next);
            current_size = next_size;
        }
    }
    output.commit();
}

void decrypt_file(const fs::path& key_path, const fs::path& input_path,
                  const fs::path& output_path) {
    if (path_entry_exists(output_path)) {
        fail("Refusing to overwrite existing output: " + display_path(output_path));
    }
    InputFile input(input_path, "Container file");
    auto master_key = unicode_to_key_bytes(key_path);
    CleanseGuard master_key_guard(master_key.data(), master_key.size());

    std::array<unsigned char, kHeaderSize> header{};
    input.read_exact(header.data(), header.size(), "container header");
    if (!std::equal(kMagic.begin(), kMagic.end(), header.begin())) fail("Not an RCTS container");
    if (header[8] != kVersion) fail("Unsupported RCTS version");
    if (get_u32(header.data() + 9) != kChunkSize) fail("Unsupported chunk size");
    auto file_key = derive_file_key(master_key, header.data() + 13);
    CleanseGuard file_key_guard(file_key.data(), file_key.size());

    AtomicOutput output(output_path);
    std::uint64_t index = 0;
    bool final_seen = false;
    while (!final_seen) {
        std::array<unsigned char, kRecordHeaderSize> record_header{};
        input.read_exact(record_header.data(), record_header.size(), "record header");
        const std::uint32_t plaintext_size = get_u32(record_header.data());
        const unsigned char flags = record_header[4];
        if (flags != 0 && flags != kFinalRecord) fail("Invalid record flags");
        if (plaintext_size > kChunkSize ||
            (flags == 0 && plaintext_size != kChunkSize) ||
            (plaintext_size == 0 && (index != 0 || flags != kFinalRecord))) {
            fail("Invalid record length");
        }
        if (index >= kMaxRecords) fail("Container exceeds the v0.1 record limit");

        Bytes encrypted(static_cast<std::size_t>(plaintext_size) + kTagSize);
        input.read_exact(encrypted.data(), encrypted.size(), "encrypted record");
        const auto nonce = make_nonce(header.data() + 29, index);
        const auto aad = make_aad(header, index, plaintext_size, flags);
        Bytes plaintext;
        if (!decrypt_gcm(file_key, nonce, aad, encrypted, plaintext)) {
            fail("Authentication failed: wrong key or damaged/modified container");
        }
        CleanseGuard plaintext_guard(plaintext.data(), plaintext.size());
        if (plaintext.size() != plaintext_size) fail("Internal plaintext length mismatch");
        write_exact(output, plaintext.data(), plaintext.size());
        final_seen = flags == kFinalRecord;
        ++index;
    }

    if (input.has_more_data()) fail("Trailing bytes after final record");
    output.commit();
}

void generate_key(const fs::path& path) {
    if (path_entry_exists(path)) {
        fail("Refusing to overwrite existing key file: " + display_path(path));
    }
    std::array<unsigned char, 32> random_key{};
    CleanseGuard random_key_guard(random_key.data(), random_key.size());
    random_bytes(random_key.data(), random_key.size());
    std::string encoded = key_bytes_to_unicode(random_key);
    CleanseGuard encoded_guard(encoded.data(), encoded.size());

    AtomicOutput output(path);
    output.write(encoded.data(), encoded.size());
    output.write("\n", 1);
    output.commit();
    std::cout << "Generated 32-symbol key: " << display_path(path) << "\r\n"
              << "Keep this file private. Losing it means losing access to encrypted files.\r\n";
}

void print_usage() {
    std::cerr <<
        "RCTS Sandbox " RCTS_VERSION "\r\n"
        "Usage:\r\n"
        "  rcts keygen <key-file>\r\n"
        "  rcts encrypt <key-file> <input-file> <output.rct>\r\n"
        "  rcts decrypt <key-file> <input.rct> <output-file>\r\n";
}

bool is_command(const fs::path& value, const char* name) {
    return value == fs::path(name);
}

int run_cli(int argc, const fs::path* argv) {
    try {
        if (argc == 3 && is_command(argv[1], "keygen")) {
            generate_key(argv[2]);
            return 0;
        }
        if (argc == 5 && is_command(argv[1], "encrypt")) {
            encrypt_file(argv[2], argv[3], argv[4]);
            std::cout << "Encrypted: " << display_path(argv[4]) << "\r\n";
            return 0;
        }
        if (argc == 5 && is_command(argv[1], "decrypt")) {
            decrypt_file(argv[2], argv[3], argv[4]);
            std::cout << "Decrypted: " << display_path(argv[4]) << "\r\n";
            return 0;
        }
        print_usage();
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "rcts: error: " << error.what() << "\r\n";
        return 1;
    }
}

#ifndef _WIN32
std::vector<fs::path> collect_arguments(int argc, char** argv) {
    std::vector<fs::path> arguments;
    arguments.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) arguments.emplace_back(argv[i]);
    return arguments;
}
#else
std::vector<fs::path> collect_arguments(int argc, wchar_t** argv) {
    std::vector<fs::path> arguments;
    arguments.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) arguments.emplace_back(argv[i]);
    return arguments;
}
#endif

} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    const std::vector<fs::path> arguments = collect_arguments(argc, argv);
    return run_cli(argc, arguments.data());
}
#else
int main(int argc, char** argv) {
    const std::vector<fs::path> arguments = collect_arguments(argc, argv);
    return run_cli(argc, arguments.data());
}
#endif

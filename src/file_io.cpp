#include "file_io.hpp"
#include "crypto.hpp"
#include "key_codec.hpp"
#include "format.hpp"
#include <openssl/crypto.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>
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
namespace rcts::file_io {
using rcts::crypto::random_bytes;
[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error(message);
}

CleanseGuard::CleanseGuard(void* memory, std::size_t size) : memory_(memory), size_(size) {}
void CleanseGuard::release() noexcept { memory_ = nullptr; size_ = 0; }
CleanseGuard::~CleanseGuard() { if (memory_ != nullptr && size_ != 0) OPENSSL_cleanse(memory_, size_); }

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
#ifdef RCTS_ENABLE_FAULT_INJECTION
    const char* requested_fault = std::getenv("RCTS_FAULT");
    const bool inject_partial_write = requested_fault != nullptr &&
                                     std::string_view(requested_fault) == "partial-write";
    bool partial_write_injected = false;
#endif
    while (size > 0) {
        std::size_t request = std::min<std::size_t>(
            size, static_cast<std::size_t>(std::numeric_limits<unsigned int>::max()));
#ifdef RCTS_ENABLE_FAULT_INJECTION
        if (inject_partial_write && !partial_write_injected) {
            request = std::min(request, std::size_t{7});
        }
#endif
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
#ifdef RCTS_ENABLE_FAULT_INJECTION
        if (inject_partial_write && !partial_write_injected) {
            partial_write_injected = true;
            inject_fault("partial-write");
        }
#endif
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

// Opens and validates the descriptor, so a path replacement cannot bypass checks.
InputFile::InputFile(const fs::path& path, const char* description) : path_(path) {
    std::error_code status_error;
    if (!fs::is_regular_file(path, status_error)) {
        if (status_error == std::errc::no_such_file_or_directory) {
            fail(std::string(description) + " does not exist: " + display_path(path));
        }
        if (status_error) {
            fail("Cannot inspect " + std::string(description) + " '" + display_path(path) + "': " + status_error.message());
        }
        fail(std::string(description) + " is not a regular file: " + display_path(path));
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
InputFile::~InputFile() { close_descriptor_noexcept(descriptor_); }

std::uint64_t InputFile::size() const { return size_; }

std::size_t InputFile::read(unsigned char* buffer, std::size_t size) {
    std::size_t total = 0;
    while (total < size) {
        const std::size_t count = read_some(descriptor_, buffer + total, size - total, path_);
        if (count == 0) break;
        total += count;
    }
    return total;
}
void InputFile::read_exact(unsigned char* buffer, std::size_t size, const char* what) {
    std::size_t total = 0;
    while (total < size) {
        const std::size_t count = read_some(descriptor_, buffer + total, size - total, path_);
        if (count == 0) fail(std::string("Truncated container while reading ") + what);
        total += count;
    }
}

bool InputFile::has_more_data() {
    unsigned char byte = 0;
    return read_some(descriptor_, &byte, 1, path_) == 1;
}
void InputFile::validate_descriptor(const char* description) {
#ifdef _WIN32
    struct _stat64 info {};
    if (_fstat64(descriptor_, &info) != 0) {
        fail("Cannot inspect " + std::string(description) + " '" + display_path(path_) + "': " + errno_message(errno));
    }
    if ((info.st_mode & _S_IFMT) != _S_IFREG) {
        fail(std::string(description) + " is not a regular file: " + display_path(path_));
    }
    size_ = static_cast<std::uint64_t>(info.st_size);
#else
    struct stat info {};
    if (fstat(descriptor_, &info) != 0) {
        fail("Cannot inspect " + std::string(description) + " '" + display_path(path_) + "': " + errno_message(errno));
    }
    if (!S_ISREG(info.st_mode)) {
        fail(std::string(description) + " is not a regular file: " + display_path(path_));
    }
    size_ = static_cast<std::uint64_t>(info.st_size);
#endif
}

void unicode_to_key_bytes(const fs::path& path,
                         std::array<unsigned char, 32>& key) {
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
    std::size_t encoded_size = count;
    if (encoded_size >= 2 && buffer[encoded_size - 2] == '\r' &&
        buffer[encoded_size - 1] == '\n') {
        encoded_size -= 2;
    } else if (encoded_size >= 1 && buffer[encoded_size - 1] == '\n') {
        --encoded_size;
    }

    if (encoded_size != 96) {
        fail("Invalid key: expected exactly 32 Unicode code points from U+4E00..U+4EFF");
    }

    if (!rcts::key_codec::decode(reinterpret_cast<const unsigned char*>(buffer.data()), key))
        fail("Invalid key: unsupported Unicode character or malformed UTF-8");
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

// Writes a sibling temporary and publishes without clobbering.
AtomicOutput::AtomicOutput(const fs::path& destination)
    : destination_(destination), temp_path_(make_temp_path(destination)) {
    inject_fault("create");
    descriptor_ = create_exclusive_writable_file(temp_path_);
}

AtomicOutput::~AtomicOutput() {
    close_noexcept();
    if (!committed_) {
        std::error_code ignored;
        fs::remove(temp_path_, ignored);
    }
}

void AtomicOutput::write(const void* data, std::size_t size) {
    if (size == 0) return;
    if (descriptor_ < 0) fail("Output file is already closed");
    inject_fault("write");
    write_all(descriptor_, data, size, temp_path_);
}

void AtomicOutput::commit() {
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

void AtomicOutput::close_checked() {
    if (descriptor_ < 0) return;
    const int descriptor = descriptor_;
    descriptor_ = -1;
    close_descriptor(descriptor, temp_path_);
}

void AtomicOutput::close_noexcept() {
    if (descriptor_ < 0) return;
    const int descriptor = descriptor_;
    descriptor_ = -1;
    close_descriptor_noexcept(descriptor);
}

} // namespace rcts::file_io

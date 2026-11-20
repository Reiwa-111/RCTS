#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>

namespace rcts::file_io {

[[noreturn]] void fail(const std::string& message);
std::string display_path(const std::filesystem::path& path);
bool path_entry_exists(const std::filesystem::path& path);
void unicode_to_key_bytes(const std::filesystem::path& path,
                        std::array<unsigned char, 32>& key);

class CleanseGuard {
public:
    CleanseGuard(void* memory, std::size_t size);
    CleanseGuard(const CleanseGuard&) = delete;
    CleanseGuard& operator=(const CleanseGuard&) = delete;
    void release() noexcept;
    ~CleanseGuard();

private:
    void* memory_;
    std::size_t size_;
};

class InputFile {
public:
    InputFile(const std::filesystem::path& path, const char* description);
    InputFile(const InputFile&) = delete;
    InputFile& operator=(const InputFile&) = delete;
    ~InputFile();

    std::uint64_t size() const;
    std::size_t read(unsigned char* buffer, std::size_t size);
    void read_exact(unsigned char* buffer, std::size_t size, const char* what);
    bool has_more_data();

private:
    void validate_descriptor(const char* description);

    std::filesystem::path path_;
    int descriptor_ = -1;
    std::uint64_t size_ = 0;
};

class AtomicOutput {
public:
    explicit AtomicOutput(const std::filesystem::path& destination);
    AtomicOutput(const AtomicOutput&) = delete;
    AtomicOutput& operator=(const AtomicOutput&) = delete;
    ~AtomicOutput();

    void write(const void* data, std::size_t size);
    void commit();

private:
    void close_checked();
    void close_noexcept();

    std::filesystem::path destination_;
    std::filesystem::path temp_path_;
    int descriptor_ = -1;
    bool committed_ = false;
};

} // namespace rcts::file_io

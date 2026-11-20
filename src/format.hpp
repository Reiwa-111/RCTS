#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace rcts::format {

inline constexpr std::array<unsigned char, 8> kMagic{
    'R', 'C', 'T', 'S', '\r', '\n', 0x1A, '\n'};
inline constexpr unsigned char kLegacyVersion = 1;
inline constexpr unsigned char kVersion = 3;
inline constexpr std::uint32_t kChunkSize = 1024U * 1024U;
inline constexpr std::size_t kSaltSize = 16;
inline constexpr std::size_t kNoncePrefixSize = 4;
inline constexpr std::size_t kTagSize = 16;
inline constexpr std::size_t kHeaderSize = 8 + 1 + 4 + kSaltSize + kNoncePrefixSize;
inline constexpr std::size_t kRecordHeaderSize = 5;
inline constexpr unsigned char kFinalRecord = 1;
inline constexpr std::uint32_t kMaxRecords = 1U << 16;
inline constexpr std::uint64_t kMaxPlaintextSize =
    static_cast<std::uint64_t>(kMaxRecords) * kChunkSize;

// Byte-order helpers used by the fixed RCTS v0.1 record framing.
inline void put_u32(unsigned char* destination, std::uint32_t value) noexcept {
    destination[0] = static_cast<unsigned char>(value >> 24U);
    destination[1] = static_cast<unsigned char>(value >> 16U);
    destination[2] = static_cast<unsigned char>(value >> 8U);
    destination[3] = static_cast<unsigned char>(value);
}

inline void put_u64(unsigned char* destination, std::uint64_t value) noexcept {
    for (int i = 7; i >= 0; --i) {
        destination[i] = static_cast<unsigned char>(value);
        value >>= 8U;
    }
}

inline std::uint32_t get_u32(const unsigned char* source) noexcept {
    return (static_cast<std::uint32_t>(source[0]) << 24U) |
           (static_cast<std::uint32_t>(source[1]) << 16U) |
           (static_cast<std::uint32_t>(source[2]) << 8U) |
           static_cast<std::uint32_t>(source[3]);
}

inline std::array<unsigned char, 12> make_nonce(const unsigned char* prefix,
                                                std::uint64_t index) noexcept {
    std::array<unsigned char, 12> nonce{};
    std::copy_n(prefix, kNoncePrefixSize, nonce.begin());
    put_u64(nonce.data() + kNoncePrefixSize, index);
    return nonce;
}

inline std::vector<unsigned char> make_aad(
    const std::array<unsigned char, kHeaderSize>& header, std::uint64_t index,
    std::uint32_t plaintext_size, unsigned char flags) {
    std::vector<unsigned char> aad(header.begin(), header.end());
    const std::size_t old_size = aad.size();
    aad.resize(old_size + 8 + 4 + 1);
    put_u64(aad.data() + old_size, index);
    put_u32(aad.data() + old_size + 8, plaintext_size);
    aad[old_size + 12] = flags;
    return aad;
}

} // namespace rcts::format

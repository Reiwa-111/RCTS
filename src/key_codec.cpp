#include "key_codec.hpp"

namespace rcts::key_codec {

void encode(const std::array<unsigned char, 32>& key,
           std::array<unsigned char, 96>& encoded) noexcept {
    // U+4E00..U+4EFF is a fixed 256-code-point alphabet, one byte per code point.
    for (std::size_t i = 0; i < key.size(); ++i) {
        const unsigned char byte = key[i];
        encoded[i * 3] = 0xE4;
        encoded[i * 3 + 1] = static_cast<unsigned char>(0xB8U + (byte >> 6U));
        encoded[i * 3 + 2] = static_cast<unsigned char>(0x80U + (byte & 0x3FU));
    }
}

bool decode(const unsigned char* encoded,
            std::array<unsigned char, 32>& key) noexcept {
    for (std::size_t i = 0; i < key.size(); ++i) {
        const auto b0 = encoded[i * 3];
        const auto b1 = encoded[i * 3 + 1];
        const auto b2 = encoded[i * 3 + 2];
        if (b0 != 0xE4 || b1 < 0xB8 || b1 > 0xBB || b2 < 0x80 || b2 > 0xBF) {
            return false;
        }
        key[i] = static_cast<unsigned char>(((b1 - 0xB8) << 6U) | (b2 - 0x80));
    }
    return true;
}

} // namespace rcts::key_codec

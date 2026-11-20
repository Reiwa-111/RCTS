#pragma once

#include <array>
#include <cstddef>

namespace rcts::key_codec {

void encode(const std::array<unsigned char, 32>& key,
           std::array<unsigned char, 96>& encoded) noexcept;
bool decode(const unsigned char* encoded,
           std::array<unsigned char, 32>& key) noexcept;

} // namespace rcts::key_codec

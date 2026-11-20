#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace rcts::crypto {

void random_bytes(unsigned char* destination, std::size_t size);

void derive_file_key(const std::array<unsigned char, 32>& master,
                    const unsigned char* salt,
                    std::array<unsigned char, 32>& result,
                    unsigned char container_version);

std::vector<unsigned char> encrypt_gcm(
    const std::array<unsigned char, 32>& key,
    const std::array<unsigned char, 12>& nonce,
    const std::vector<unsigned char>& aad,
    const unsigned char* plaintext, std::size_t plaintext_size);

bool decrypt_gcm(const std::array<unsigned char, 32>& key,
                const std::array<unsigned char, 12>& nonce,
                const std::vector<unsigned char>& aad,
                const std::vector<unsigned char>& ciphertext_and_tag,
                std::vector<unsigned char>& plaintext);

} // namespace rcts::crypto

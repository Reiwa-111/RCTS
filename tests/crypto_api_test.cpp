#include "../src/crypto.hpp"

#include <array>
#include <iostream>
#include <vector>

int main() {
    const std::array<unsigned char, 32> key{};
    const std::array<unsigned char, 12> nonce{};
    const std::vector<unsigned char> aad{0x52, 0x43, 0x54, 0x53};
    const std::vector<unsigned char> message{0x73, 0x65, 0x63, 0x72, 0x65, 0x74};
    const auto sealed = rcts::crypto::encrypt_gcm(
        key, nonce, aad, message.data(), message.size());

    std::vector<unsigned char> plaintext{0xAA, 0xBB, 0xCC};
    if (!rcts::crypto::decrypt_gcm(key, nonce, aad, sealed, plaintext) ||
        plaintext != message) {
        std::cerr << "crypto API test: successful decrypt failed\n";
        return 1;
    }

    const std::vector<unsigned char> too_short{0x01, 0x02};
    if (rcts::crypto::decrypt_gcm(key, nonce, aad, too_short, plaintext) ||
        !plaintext.empty()) {
        std::cerr << "crypto API test: short input did not clear output\n";
        return 1;
    }

    auto corrupted = sealed;
    corrupted.back() ^= 0x01;
    if (rcts::crypto::decrypt_gcm(key, nonce, aad, corrupted, plaintext) ||
        !plaintext.empty()) {
        std::cerr << "crypto API test: authentication failure did not clear output\n";
        return 1;
    }

    std::cout << "crypto API output-reuse checks passed\n";
    return 0;
}

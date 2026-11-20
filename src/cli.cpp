#include "entry.hpp"
#include "operations.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

#ifndef RCTS_VERSION
#define RCTS_VERSION "0.3.0"
#endif

namespace fs = std::filesystem;

namespace {
std::string display_path(const fs::path& path) {
    const std::u8string encoded = path.u8string();
    return std::string(reinterpret_cast<const char*>(encoded.data()), encoded.size());
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
} // namespace

namespace rcts {

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

} // namespace rcts

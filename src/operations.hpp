#pragma once

#include <filesystem>

namespace rcts {

void generate_key(const std::filesystem::path& path);
void encrypt_file(const std::filesystem::path& key_path,
                 const std::filesystem::path& input_path,
                 const std::filesystem::path& output_path);
void decrypt_file(const std::filesystem::path& key_path,
                 const std::filesystem::path& input_path,
                 const std::filesystem::path& output_path);

} // namespace rcts

#include "operations.hpp"

#include "crypto.hpp"
#include "file_io.hpp"
#include "format.hpp"
#include "key_codec.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

namespace fs = std::filesystem;

namespace rcts {
using Bytes = std::vector<unsigned char>;
using namespace file_io;

using crypto::decrypt_gcm;
using crypto::derive_file_key;
using crypto::encrypt_gcm;
using crypto::random_bytes;

using format::kChunkSize;
using format::kFinalRecord;
using format::kHeaderSize;
using format::kMagic;
using format::kMaxPlaintextSize;
using format::kMaxRecords;
using format::kNoncePrefixSize;
using format::kRecordHeaderSize;
using format::kSaltSize;
using format::kTagSize;
using format::kVersion;
using format::kLegacyVersion;
using format::make_aad;
using format::make_nonce;
using format::get_u32;
using format::put_u32;

namespace {

void write_exact(AtomicOutput& output, const unsigned char* source,
                std::size_t size) {
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

} // namespace

void encrypt_file(const fs::path& key_path, const fs::path& input_path,
                 const fs::path& output_path) {
    if (path_entry_exists(output_path)) {
        fail("Refusing to overwrite existing output: " + display_path(output_path));
    }

    InputFile input(input_path, "Input file");
    if (input.size() > kMaxPlaintextSize) {
        fail("Container exceeds the v0.3 record limit");
    }

    std::array<unsigned char, 32> master_key{};
    CleanseGuard master_key_guard(master_key.data(), master_key.size());
    unicode_to_key_bytes(key_path, master_key);

    std::array<unsigned char, kHeaderSize> header{};
    std::copy(kMagic.begin(), kMagic.end(), header.begin());
    header[8] = kVersion;
    put_u32(header.data() + 9, kChunkSize);
    random_bytes(header.data() + 13, kSaltSize);
    random_bytes(header.data() + 29, kNoncePrefixSize);

    std::array<unsigned char, 32> file_key{};
    CleanseGuard file_key_guard(file_key.data(), file_key.size());
    derive_file_key(master_key, header.data() + 13, file_key, kVersion);

    AtomicOutput output(output_path);
    write_exact(output, header.data(), header.size());

    Bytes current(kChunkSize), next(kChunkSize);
    CleanseGuard current_guard(current.data(), current.size());
    CleanseGuard next_guard(next.data(), next.size());
    std::size_t current_size = read_chunk(input, current);
    std::uint64_t index = 0;

    if (current_size == 0) {
        write_record(output, header, file_key, index, current.data(), 0,
                    kFinalRecord);
    } else {
        while (true) {
            const std::size_t next_size = read_chunk(input, next);
            const bool final = next_size == 0;
            if (index >= kMaxRecords) {
                fail("Container exceeds the v0.3 record limit");
            }

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
    std::array<unsigned char, 32> master_key{};
    CleanseGuard master_key_guard(master_key.data(), master_key.size());
    unicode_to_key_bytes(key_path, master_key);

    std::array<unsigned char, kHeaderSize> header{};
    input.read_exact(header.data(), header.size(), "container header");
    if (!std::equal(kMagic.begin(), kMagic.end(), header.begin())) {
        fail("Not an RCTS container");
    }

    const unsigned char container_version = header[8];
    if (container_version != kLegacyVersion && container_version != kVersion) {
        fail("Unsupported RCTS version");
    }
    if (get_u32(header.data() + 9) != kChunkSize) {
        fail("Unsupported chunk size");
    }

    std::array<unsigned char, 32> file_key{};
    CleanseGuard file_key_guard(file_key.data(), file_key.size());
    derive_file_key(master_key, header.data() + 13, file_key,
                    container_version);

    AtomicOutput output(output_path);
    std::uint64_t index = 0;
    bool final_seen = false;
    while (!final_seen) {
        std::array<unsigned char, kRecordHeaderSize> record_header{};
        input.read_exact(record_header.data(), record_header.size(), "record header");
        const std::uint32_t plaintext_size = get_u32(record_header.data());
        const unsigned char flags = record_header[4];

        if (flags != 0 && flags != kFinalRecord) {
            fail("Invalid record flags");
        }
        if (plaintext_size > kChunkSize ||
            (flags == 0 && plaintext_size != kChunkSize) ||
            (plaintext_size == 0 && (index != 0 || flags != kFinalRecord))) {
            fail("Invalid record length");
        }
        if (index >= kMaxRecords) {
            fail("Container exceeds the v0.3 record limit");
        }

        Bytes encrypted(static_cast<std::size_t>(plaintext_size) + kTagSize);
        input.read_exact(encrypted.data(), encrypted.size(), "encrypted record");
        const auto nonce = make_nonce(header.data() + 29, index);
        const auto aad = make_aad(header, index, plaintext_size, flags);

        Bytes plaintext;
        if (!decrypt_gcm(file_key, nonce, aad, encrypted, plaintext)) {
            fail("Authentication failed: wrong key or damaged/modified container");
        }
        CleanseGuard plaintext_guard(plaintext.data(), plaintext.size());
        if (plaintext.size() != plaintext_size) {
            fail("Internal plaintext length mismatch");
        }
        write_exact(output, plaintext.data(), plaintext.size());

        final_seen = flags == kFinalRecord;
        ++index;
    }

    if (input.has_more_data()) {
        fail("Trailing bytes after final record");
    }
    output.commit();
}

void generate_key(const fs::path& path) {
    if (path_entry_exists(path)) {
        fail("Refusing to overwrite existing key file: " + display_path(path));
    }

    std::array<unsigned char, 32> random_key{};
    CleanseGuard random_key_guard(random_key.data(), random_key.size());
    random_bytes(random_key.data(), random_key.size());

    std::array<unsigned char, 96> encoded{};
    CleanseGuard encoded_guard(encoded.data(), encoded.size());
    key_codec::encode(random_key, encoded);

    AtomicOutput output(path);
    output.write(encoded.data(), encoded.size());
    output.write("\n", 1);
    output.commit();

    std::cout << "Generated 32-symbol key: " << display_path(path) << "\r\n"
              << "Keep this file private. Losing it means losing access to encrypted files.\r\n";
}

} // namespace rcts

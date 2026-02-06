#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include "integrity.h"

struct Packet {
    std::vector<std::byte> bytes;
};

struct ChunkManifestEntry {
    uint32_t chunk_index = 0;
    uint32_t chunk_size = 0;
    uint32_t original_size = 0;
    Sha256Digest sha256{};
    uint32_t N = 0;
    uint16_t T = 0;
};

class Encoder {
public:
    using FileId = std::array<std::byte, 16>;

    explicit Encoder(FileId file_id);

    [[nodiscard]] std::pair<std::vector<Packet>, ChunkManifestEntry>
    encode_chunk(uint32_t chunk_index, std::span<const std::byte> chunk_data, bool is_last_chunk) const;

    [[nodiscard]] const FileId &file_id() const { return id; }

private:
    FileId id;

    [[nodiscard]] std::vector<std::byte> create_packet_header(
        uint32_t chunk_index,
        uint32_t chunk_size,
        uint16_t symbol_size,
        uint32_t num_source,
        uint32_t block_id,
        uint16_t payload_length,
        uint8_t flags,
        std::span<const std::byte> payload
    ) const;
};

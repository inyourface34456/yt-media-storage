#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>

struct ChunkSlice {
    std::size_t offset = 0;
    std::size_t length = 0;
};

struct ChunkedStorageData {
    std::vector<std::byte> storage;
    std::vector<ChunkSlice> chunks;
};

ChunkedStorageData chunkByteData(std::span<const std::byte> data);

ChunkedStorageData chunkFile(const char *path);

inline std::span<const std::byte> chunkSpan(const ChunkedStorageData &cs, std::size_t i) {
    const auto &c = cs.chunks[i];
    return {cs.storage.data() + c.offset, c.length};
}

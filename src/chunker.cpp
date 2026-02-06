#include "chunker.h"
#include "configuration.h"

#include <algorithm>
#include <fstream>
#include <stdexcept>

ChunkedStorageData chunkByteData(std::span<const std::byte> data) {
    ChunkedStorageData result;
    result.storage.assign(data.begin(), data.end());

    const std::size_t size = result.storage.size();
    result.chunks.reserve((size + CHUNK_SIZE_BYTES - 1) / CHUNK_SIZE_BYTES);

    for (std::size_t off = 0; off < size; off += CHUNK_SIZE_BYTES) {
        const std::size_t len = (std::min<std::size_t>)(CHUNK_SIZE_BYTES, size - off);
        result.chunks.push_back(ChunkSlice{off, len});
    }

    return result;
}

ChunkedStorageData chunkFile(const char *path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("open failed");
    }

    const std::size_t size = file.tellg();
    file.seekg(0);

    ChunkedStorageData result;
    result.storage.resize(size);
    if (!file.read(reinterpret_cast<char *>(result.storage.data()), size)) {
        throw std::runtime_error("read failed");
    }

    result.chunks.reserve((size + CHUNK_SIZE_BYTES - 1) / CHUNK_SIZE_BYTES);

    for (std::size_t off = 0; off < size; off += CHUNK_SIZE_BYTES) {
        const std::size_t len = (std::min<std::size_t>)(CHUNK_SIZE_BYTES, size - off);
        result.chunks.push_back(ChunkSlice{off, len});
    }

    return result;
}

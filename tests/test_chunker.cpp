#include <gtest/gtest.h>
#include "chunker.h"
#include "configuration.h"
#include <filesystem>
#include <fstream>
#include <atomic>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
    std::filesystem::path make_unique_temp_path() {
        static std::atomic<std::uint64_t> seq{0};
        return std::filesystem::temp_directory_path() /
               ("chunker_test_" + std::to_string(seq.fetch_add(1)) + ".bin");
    }

    struct TempFile {
        std::filesystem::path path;

        explicit TempFile(const std::vector<std::byte> &data) : path(make_unique_temp_path()) {
            std::ofstream out(path, std::ios::binary);
            if (!out) {
                throw std::runtime_error("open failed");
            }
            out.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
        }

        ~TempFile() {
            std::error_code ec;
            std::filesystem::remove(path, ec);
        }

        TempFile(const TempFile &) = delete;

        TempFile &operator=(const TempFile &) = delete;

        TempFile(TempFile &&) = delete;

        TempFile &operator=(TempFile &&) = delete;
    };
}

TEST(Chunker, ChunkByteData_EmptyInput) {
    constexpr std::vector<std::byte> data;
    const auto [storage, chunks] = chunkByteData(std::span(data.data(), data.size()));
    ASSERT_EQ(chunks.size(), 1u);
    EXPECT_EQ(chunks[0].offset, 0u);
    EXPECT_EQ(chunks[0].length, 0u);
    EXPECT_TRUE(storage.empty());
}

TEST(Chunker, ChunkByteData_SmallInput) {
    std::vector<std::byte> data(100);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>(static_cast<unsigned char>(i));
    }
    const auto [storage, chunks] = chunkByteData(std::span<const std::byte>(data.data(), data.size()));
    ASSERT_EQ(chunks.size(), 1u);
    EXPECT_EQ(chunks[0].offset, 0u);
    EXPECT_EQ(chunks[0].length, 100u);
}

TEST(Chunker, ChunkByteData_ExactChunkSize) {
    std::vector<std::byte> data(CHUNK_SIZE_BYTES);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>(static_cast<unsigned char>(i & 0xFF));
    }
    const auto [storage, chunks] = chunkByteData(std::span<const std::byte>(data.data(), data.size()));
    ASSERT_EQ(chunks.size(), 1u);
    EXPECT_EQ(chunks[0].offset, 0u);
    EXPECT_EQ(chunks[0].length, CHUNK_SIZE_BYTES);
}

TEST(Chunker, ChunkByteData_MultipleChunks) {
    constexpr std::size_t total = CHUNK_SIZE_BYTES * 2 + CHUNK_SIZE_BYTES / 2;
    std::vector<std::byte> data(total);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>(static_cast<unsigned char>(i & 0xFF));
    }
    const auto [storage, chunks] = chunkByteData(std::span<const std::byte>(data.data(), data.size()));
    ASSERT_EQ(chunks.size(), 3u);
    EXPECT_EQ(chunks[0].length, CHUNK_SIZE_BYTES);
    EXPECT_EQ(chunks[1].length, CHUNK_SIZE_BYTES);
    EXPECT_EQ(chunks[2].length, CHUNK_SIZE_BYTES / 2);
}

TEST(Chunker, ChunkByteData_StoragePreservesData) {
    std::vector<std::byte> data(5000);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>(static_cast<unsigned char>((i * 17) & 0xFF));
    }
    const auto [storage, chunks] = chunkByteData(std::span<const std::byte>(data.data(), data.size()));
    ASSERT_EQ(storage.size(), data.size());
    EXPECT_EQ(storage, data);
}

TEST(Chunker, ChunkSpan_ReturnsCorrectSlice) {
    constexpr std::size_t total = CHUNK_SIZE_BYTES + 42;
    std::vector<std::byte> data(total);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>(static_cast<unsigned char>(i & 0xFF));
    }
    const ChunkedStorageData cs = chunkByteData(std::span<const std::byte>(data.data(), data.size()));
    ASSERT_EQ(cs.chunks.size(), 2u);
    for (std::size_t i = 0; i < cs.chunks.size(); ++i) {
        const std::span<const std::byte> sp = chunkSpan(cs, i);
        EXPECT_EQ(sp.size(), cs.chunks[i].length);
        EXPECT_EQ(sp.data(), cs.storage.data() + cs.chunks[i].offset);
        for (std::size_t j = 0; j < sp.size(); ++j) {
            EXPECT_EQ(sp[j], cs.storage[cs.chunks[i].offset + j]);
        }
    }
}

TEST(Chunker, ChunkFile_MatchesByteData) {
    constexpr std::size_t total = CHUNK_SIZE_BYTES + 99;
    std::vector<std::byte> data(total);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>(static_cast<unsigned char>((i * 3) & 0xFF));
    }
    const TempFile f(data);
    const auto [storage, chunks] =
            chunkByteData(std::span<const std::byte>(data.data(), data.size()));
    const auto [from_storage, from_chunks] = chunkFile(f.path.string().c_str());
    EXPECT_EQ(storage, from_storage);
    ASSERT_EQ(chunks.size(), from_chunks.size());
    for (std::size_t i = 0; i < chunks.size(); ++i) {
        EXPECT_EQ(chunks[i].offset, from_chunks[i].offset);
        EXPECT_EQ(chunks[i].length, from_chunks[i].length);
    }
}

TEST(Chunker, FileChunkReader_NumChunks) { {
        TempFile f({});
        FileChunkReader r(f.path.string().c_str());
        EXPECT_EQ(r.num_chunks(), 1u);
        EXPECT_EQ(r.file_size(), 0u);
        EXPECT_EQ(r.chunk_size(), CHUNK_SIZE_BYTES);
    } {
        std::vector<std::byte> one(1);
        one[0] = static_cast<std::byte>(0xAB);
        TempFile f(one);
        FileChunkReader r(f.path.string().c_str());
        EXPECT_EQ(r.num_chunks(), 1u);
        EXPECT_EQ(r.file_size(), 1u);
    } {
        std::vector<std::byte> exact(CHUNK_SIZE_BYTES);
        TempFile f(exact);
        FileChunkReader r(f.path.string().c_str());
        EXPECT_EQ(r.num_chunks(), 1u);
        EXPECT_EQ(r.file_size(), CHUNK_SIZE_BYTES);
    } {
        std::vector<std::byte> over(CHUNK_SIZE_BYTES + 1);
        TempFile f(over);
        FileChunkReader r(f.path.string().c_str());
        EXPECT_EQ(r.num_chunks(), 2u);
        EXPECT_EQ(r.file_size(), CHUNK_SIZE_BYTES + 1);
    }
}

TEST(Chunker, FileChunkReader_ReadChunk) {
    constexpr std::size_t total = CHUNK_SIZE_BYTES + 50;
    std::vector<std::byte> data(total);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>(static_cast<unsigned char>((i * 11) & 0xFF));
    }
    TempFile f(data);
    FileChunkReader r(f.path.string().c_str());
    ASSERT_EQ(r.num_chunks(), 2u);
    std::vector<std::byte> c0 = r.read_chunk(0);
    std::vector<std::byte> c1 = r.read_chunk(1);
    ASSERT_EQ(c0.size(), CHUNK_SIZE_BYTES);
    ASSERT_EQ(c1.size(), 50u);
    for (std::size_t i = 0; i < CHUNK_SIZE_BYTES; ++i) {
        EXPECT_EQ(c0[i], data[i]);
    }
    for (std::size_t i = 0; i < 50u; ++i) {
        EXPECT_EQ(c1[i], data[CHUNK_SIZE_BYTES + i]);
    }
}

TEST(Chunker, FileChunkReader_CustomChunkSize) {
    constexpr std::size_t kChunk = 100;
    constexpr std::size_t total = 250;
    std::vector<std::byte> data(total);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>(static_cast<unsigned char>(i & 0xFF));
    }
    TempFile f(data);
    FileChunkReader r(f.path.string().c_str(), kChunk);
    EXPECT_EQ(r.chunk_size(), kChunk);
    EXPECT_EQ(r.num_chunks(), 3u);
    std::vector<std::byte> a = r.read_chunk(0);
    std::vector<std::byte> b = r.read_chunk(1);
    std::vector<std::byte> c = r.read_chunk(2);
    ASSERT_EQ(a.size(), 100u);
    ASSERT_EQ(b.size(), 100u);
    ASSERT_EQ(c.size(), 50u);
    for (std::size_t i = 0; i < 100; ++i) {
        EXPECT_EQ(a[i], data[i]);
        EXPECT_EQ(b[i], data[100 + i]);
    }
    for (std::size_t i = 0; i < 50; ++i) {
        EXPECT_EQ(c[i], data[200 + i]);
    }
}

TEST(Chunker, FileChunkReader_OutOfRange) {
    const std::vector<std::byte> data(10);
    const TempFile f(data);
    const FileChunkReader r(f.path.string().c_str());
    EXPECT_THROW(static_cast<void>(r.read_chunk(r.num_chunks())), std::runtime_error);
}

#include <gtest/gtest.h>

#include "chunker.h"
#include "configuration.h"
#include "crypto.h"
#include "decoder.h"
#include "encoder.h"
#include "integrity.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

Encoder::FileId make_file_id() {
    Encoder::FileId id{};
    for (std::size_t i = 0; i < id.size(); ++i) {
        id[i] = std::byte{static_cast<uint8_t>(i)};
    }
    return id;
}

std::vector<std::byte> make_data(const std::size_t n) {
    std::vector<std::byte> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = std::byte{static_cast<uint8_t>(i % 251)};
    }
    return v;
}

void encode_and_feed(const Encoder &enc, Decoder &dec,
                     const std::span<const std::byte> chunk_data,
                     const uint32_t chunk_index, const bool is_last) {
    for (auto [packets, manifest] = enc.encode_chunk(chunk_index, chunk_data, is_last); const auto &[bytes] : packets) {
        (void)dec.process_packet(
            std::span(bytes.data(), bytes.size()), false);
    }
}

} // namespace

TEST(Roundtrip, SingleChunk) {
    const auto original = make_data(4096);
    const auto file_id = make_file_id();
    const Encoder enc(file_id);
    Decoder dec;

    encode_and_feed(enc, dec, original, 0, true);

    EXPECT_EQ(dec.chunks_completed(), 1u);
    const auto assembled = dec.assemble_file(1);
    ASSERT_TRUE(assembled.has_value());
    EXPECT_EQ(*assembled, original);
}

TEST(Roundtrip, MultipleChunks) {
    constexpr std::size_t total_size = CHUNK_SIZE_BYTES * 2 + 5000;
    const auto original = make_data(total_size);
    const auto file_id = make_file_id();
    const Encoder enc(file_id);
    Decoder dec;

    const auto chunked = chunkByteData(original);
    const uint32_t num_chunks = static_cast<uint32_t>(chunked.chunks.size());

    for (uint32_t i = 0; i < num_chunks; ++i) {
        const auto span = chunkSpan(chunked, i);
        encode_and_feed(enc, dec, span, i, i == num_chunks - 1);
    }

    EXPECT_EQ(dec.chunks_completed(), num_chunks);
    const auto assembled = dec.assemble_file(num_chunks);
    ASSERT_TRUE(assembled.has_value());
    EXPECT_EQ(*assembled, original);
}

TEST(Roundtrip, SmallData) {
    const auto original = make_data(10);
    const auto file_id = make_file_id();
    const Encoder enc(file_id);
    Decoder dec;

    encode_and_feed(enc, dec, original, 0, true);

    const auto assembled = dec.assemble_file(1);
    ASSERT_TRUE(assembled.has_value());
    EXPECT_EQ(*assembled, original);
}

TEST(Roundtrip, WithEncryption) {
    const auto original = make_data(8192);
    const auto file_id = make_file_id();
    const Encoder enc(file_id);
    Decoder dec;

    constexpr std::byte password[] = {
        std::byte{'t'}, std::byte{'e'}, std::byte{'s'}, std::byte{'t'}};
    auto key = derive_key(std::span(password), file_id);

    auto encrypted = encrypt_chunk(original, key, file_id, 0);
    auto [packets, manifest] =
        enc.encode_chunk(0, encrypted, true, true);

    for (const auto &[bytes] : packets) {
        (void)dec.process_packet(
            std::span(bytes.data(), bytes.size()), false);
    }

    EXPECT_TRUE(dec.is_encrypted());
    dec.set_decrypt_key(key);

    const auto assembled = dec.assemble_file(1);
    ASSERT_TRUE(assembled.has_value());
    EXPECT_EQ(*assembled, original);

    dec.clear_decrypt_key();
    secure_zero(std::span<std::byte>(key));
}

TEST(Roundtrip, WithXXHash) {
    const auto original = make_data(4096);
    const auto file_id = make_file_id();
    const Encoder enc(file_id, HashAlgorithm::XXHash32);
    Decoder dec;

    encode_and_feed(enc, dec, original, 0, true);

    const auto assembled = dec.assemble_file(1);
    ASSERT_TRUE(assembled.has_value());
    EXPECT_EQ(*assembled, original);
}

TEST(Roundtrip, AssembleFile_IncompleteChunks) {
    const auto original = make_data(4096);
    const auto file_id = make_file_id();
    const Encoder enc(file_id);
    Decoder dec;

    encode_and_feed(enc, dec, original, 0, false);

    EXPECT_FALSE(dec.assemble_file(2).has_value());
}

TEST(Roundtrip, MultipleChunks_Sha256Verify) {
    constexpr std::size_t total_size = CHUNK_SIZE_BYTES + 1000;
    const auto original = make_data(total_size);
    const auto file_id = make_file_id();
    const Encoder enc(file_id);
    Decoder dec;

    const auto chunked = chunkByteData(original);
    const uint32_t num_chunks = static_cast<uint32_t>(chunked.chunks.size());

    for (uint32_t i = 0; i < num_chunks; ++i) {
        const auto span = chunkSpan(chunked, i);
        auto [packets, manifest] = enc.encode_chunk(i, span, i == num_chunks - 1);

        const Sha256Digest expected_sha = sha256(span);
        EXPECT_EQ(manifest.sha256, expected_sha);

        for (const auto &[bytes] : packets) {
            (void)dec.process_packet(
                std::span(bytes.data(), bytes.size()), false);
        }
    }

    const auto assembled = dec.assemble_file(num_chunks);
    ASSERT_TRUE(assembled.has_value());
    EXPECT_EQ(*assembled, original);
}

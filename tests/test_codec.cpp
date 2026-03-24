#include <gtest/gtest.h>

#include "configuration.h"
#include "decoder.h"
#include "encoder.h"
#include "integrity.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
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

uint32_t read_u32_le(const std::span<const std::byte> data) {
    uint32_t v = 0;
    std::memcpy(&v, data.data(), sizeof(v));
    return v;
}

} // namespace

TEST(Codec, Encoder_ProducesCorrectPacketCount) {
    const auto data = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, data, false);
    (void)manifest;
    EXPECT_GT(packets.size(), 0u);
    EXPECT_GE(packets.size(), 32u);
    EXPECT_LE(packets.size(), 64u);
}

TEST(Codec, Encoder_PacketHasCorrectMagic) {
    const auto data = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, data, false);
    (void)manifest;
    for (const auto &[bytes] : packets) {
        EXPECT_EQ(read_u32_le(std::span(bytes.data(), 4)), MAGIC_ID);
    }
}

TEST(Codec, Encoder_PacketHasV2Version) {
    const auto data = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, data, false);
    (void)manifest;
    for (const auto &[bytes] : packets) {
        EXPECT_EQ(static_cast<uint8_t>(bytes[VERSION_OFF]), VERSION_ID_V2);
    }
}

TEST(Codec, Encoder_ManifestMatchesInput) {
    constexpr uint32_t k_chunk_index = 7;
    const auto data = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(k_chunk_index, data, false);
    (void)packets;
    EXPECT_EQ(manifest.chunk_index, k_chunk_index);
    EXPECT_EQ(manifest.original_size, static_cast<uint32_t>(data.size()));
}

TEST(Codec, Encoder_LastChunkFlagSet) {
    const auto data = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, data, true);
    (void)manifest;
    for (const auto &[bytes] : packets) {
        const uint8_t flags = static_cast<uint8_t>(bytes[FLAGS_OFF]);
        EXPECT_NE(flags & LastChunk, 0);
    }
}

TEST(Codec, Encoder_LastChunkFlagNotSet) {
    const auto data = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, data, false);
    (void)manifest;
    for (const auto &[bytes] : packets) {
        const uint8_t flags = static_cast<uint8_t>(bytes[FLAGS_OFF]);
        EXPECT_EQ(flags & LastChunk, 0);
    }
}

TEST(Codec, Encoder_SmallDataPadded) {
    const auto data = make_data(100);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, data, false);
    (void)packets;
    EXPECT_GE(manifest.chunk_size, static_cast<uint32_t>(SYMBOL_SIZE_BYTES * 2));
}

TEST(Codec, Decoder_ParseValidPacket) {
    const auto data = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, data, false);
    (void)manifest;
    const auto parsed = Decoder::parse_packet(std::span(packets[0].bytes.data(), packets[0].bytes.size()));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->header.magic, MAGIC_ID);
    EXPECT_EQ(parsed->header.version, VERSION_ID_V2);
}

TEST(Codec, Decoder_ParseInvalidMagic) {
    const auto data = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, data, false);
    (void)manifest;
    std::vector buf(packets[0].bytes.begin(), packets[0].bytes.end());
    buf[0] = std::byte{0};
    buf[1] = std::byte{0};
    buf[2] = std::byte{0};
    buf[3] = std::byte{0};
    EXPECT_FALSE(Decoder::parse_packet(buf).has_value());
}

TEST(Codec, Decoder_ParseTruncatedPacket) {
    const auto data = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, data, false);
    (void)manifest;
    std::vector short_packet(packets[0].bytes.begin(), packets[0].bytes.begin() + 100);
    EXPECT_FALSE(Decoder::parse_packet(short_packet).has_value());
}

TEST(Codec, Decoder_ValidatePacketCrc) {
    const auto data = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, data, false);
    (void)manifest;
    const auto parsed = Decoder::parse_packet(std::span(packets[0].bytes.data(), packets[0].bytes.size()));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(Decoder::validate_packet_crc(*parsed));
}

TEST(Codec, Decoder_ValidateRawPacketCrc) {
    const auto data = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, data, false);
    (void)manifest;
    EXPECT_TRUE(Decoder::validate_raw_packet_crc(std::span(packets[0].bytes.data(), packets[0].bytes.size())));
}

TEST(Codec, Decoder_ValidateCorruptedPacket) {
    const auto data = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, data, false);
    (void)manifest;
    std::vector buf(packets[0].bytes.begin(), packets[0].bytes.end());
    buf[HEADER_SIZE_V2] ^= std::byte{0xFF};
    EXPECT_FALSE(Decoder::validate_raw_packet_crc(buf));
}

TEST(Codec, Decoder_ChunkRoundtrip) {
    const auto original = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, original, false);
    (void)manifest;
    Decoder dec;
    bool decoded = false;
    for (const auto &[bytes] : packets) {
        if (const auto r = dec.process_packet(std::span(bytes.data(), bytes.size())); r && r->success) {
            decoded = true;
        }
    }
    EXPECT_TRUE(decoded);
    EXPECT_TRUE(dec.is_chunk_complete(0));
    const auto chunk = dec.get_chunk_data(0);
    ASSERT_TRUE(chunk.has_value());
    EXPECT_EQ(*chunk, original);
}

TEST(Codec, Decoder_ChunkRoundtripWithSha256) {
    const auto original = make_data(4096);
    const Encoder enc(make_file_id());
    const auto [packets, manifest] = enc.encode_chunk(0, original, false);
    (void)manifest;
    Decoder dec;
    std::optional<ChunkDecodeResult> last;
    for (const auto &[bytes] : packets) {
        if (auto r = dec.process_packet(std::span(bytes.data(), bytes.size()), true); r && r->success) {
            last = std::move(*r);
        }
    }
    ASSERT_TRUE(last.has_value());
    EXPECT_EQ(last->sha256, sha256(std::span(original.data(), original.size())));
}

TEST(Codec, Decoder_XXHashAlgorithm) {
    const auto original = make_data(4096);
    const Encoder enc(make_file_id(), HashAlgorithm::XXHash32);
    const auto [packets, manifest] = enc.encode_chunk(0, original, false);
    (void)manifest;
    Decoder dec;
    bool decoded = false;
    for (const auto &[bytes] : packets) {
        if (const auto r = dec.process_packet(std::span(bytes.data(), bytes.size())); r && r->success) {
            decoded = true;
        }
    }
    EXPECT_TRUE(decoded);
    const auto chunk = dec.get_chunk_data(0);
    ASSERT_TRUE(chunk.has_value());
    EXPECT_EQ(*chunk, original);
}

#include <gtest/gtest.h>

#include "integrity.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

std::vector<std::byte> bytesFromString(const std::string &s) {
    std::vector<std::byte> out;
    out.reserve(s.size());
    for (const unsigned char c : s) {
        out.push_back(std::byte{c});
    }
    return out;
}

void writeU32Le(std::vector<std::byte> &buf, const std::size_t offset, const uint32_t v) {
    std::memcpy(buf.data() + offset, &v, sizeof(v));
}

} // namespace

TEST(Integrity, Sha256_EmptyInput) {
    constexpr std::vector<std::byte> empty;
    const Sha256Digest d = sha256(empty);
    EXPECT_EQ(d.hexValue(),
              "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
}

TEST(Integrity, Sha256_KnownInput) {
    const auto hello = bytesFromString("hello");
    const Sha256Digest d = sha256(hello);
    EXPECT_EQ(d.hexValue(),
              "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824");
}

TEST(Integrity, Sha256_HexValue) {
    const auto data = bytesFromString("abc");
    const Sha256Digest d = sha256(data);
    for (const std::string hex = d.hexValue(); const char c : hex) {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'));
    }
}

TEST(Integrity, Sha256_Equality) {
    const auto a = bytesFromString("same");
    const auto b = bytesFromString("diff");
    EXPECT_EQ(sha256(a), sha256(a));
    EXPECT_NE(sha256(a), sha256(b));
}

TEST(Integrity, Crc32_Deterministic) {
    const auto data = bytesFromString("deterministic");
    EXPECT_EQ(crc32c(data), crc32c(data));
}

TEST(Integrity, Crc32_DifferentInputs) {
    const auto x = bytesFromString("alpha");
    const auto y = bytesFromString("beta");
    EXPECT_NE(crc32c(x), crc32c(y));
}

TEST(Integrity, Crc32Concat_MatchesSingleCall) {
    const auto first = bytesFromString("first");
    const auto second = bytesFromString("second");
    std::vector<std::byte> combined = first;
    combined.insert(combined.end(), second.begin(), second.end());
    EXPECT_EQ(crc32c_concat(first, second), crc32c(combined));
}

TEST(Integrity, PacketChecksum_CRC32) {
    const auto header = bytesFromString("hdr");
    const auto payload = bytesFromString("pld");
    constexpr std::size_t crc_offset = 0;
    EXPECT_EQ(packet_checksum(header, payload, crc_offset, HashAlgorithm::CRC32),
              packet_crc32c(header, payload, crc_offset));
}

TEST(Integrity, PacketChecksum_XXHash) {
    const auto header = bytesFromString("hdr");
    const auto payload = bytesFromString("pld");
    constexpr std::size_t crc_offset = 0;
    EXPECT_EQ(packet_checksum(header, payload, crc_offset, HashAlgorithm::XXHash32),
              xxhash32_packet(header, payload, crc_offset));
}

TEST(Integrity, VerifyPacketCrc_ValidPacket) {
    std::vector<std::byte> header = bytesFromString("\x01\x02\x03\x04\x05\x06");
    const auto payload = bytesFromString("payload-bytes");
    constexpr std::size_t crc_offset = 2;
    const uint32_t crc = packet_crc32c(header, payload, crc_offset);
    writeU32Le(header, crc_offset, crc);
    EXPECT_TRUE(verify_packet_crc32c(header, payload, crc_offset));
}

TEST(Integrity, VerifyPacketCrc_CorruptedPayload) {
    std::vector<std::byte> header = bytesFromString("\x01\x02\x03\x04\x05\x06");
    std::vector<std::byte> payload = bytesFromString("payload-bytes");
    constexpr std::size_t crc_offset = 2;
    const uint32_t crc = packet_crc32c(header, payload, crc_offset);
    writeU32Le(header, crc_offset, crc);
    payload[0] = static_cast<std::byte>(
        static_cast<unsigned char>(payload[0]) ^ 0xFFu);
    EXPECT_FALSE(verify_packet_crc32c(header, payload, crc_offset));
}

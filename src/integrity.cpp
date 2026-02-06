#include "integrity.h"
#include "configuration.h"

#include "libs/picosha2.h"
#include "libs/CRC.h"

#include <cstring>

static std::string bytes_to_hex(const std::span<const std::byte> inputBytes) {
    std::string hexString(inputBytes.size() * 2, 0);
    auto outputPosition = hexString.data();
    for (const auto &currentByte: inputBytes) {
        const auto byteValue = std::to_integer<unsigned char>(currentByte);
        *outputPosition++ = SHA_CHARACTERS[byteValue >> 4];
        *outputPosition++ = SHA_CHARACTERS[byteValue & 0x0F];
    }
    return hexString;
}

std::string Sha256Digest::hexValue() const {
    return bytes_to_hex(std::span(bytes.data(), bytes.size()));
}

Sha256Digest sha256(const std::span<const std::byte> data) {
    Sha256Digest digest;
    const auto dataStart = reinterpret_cast<const uint8_t *>(data.data());
    const auto dataEnd = dataStart + data.size();
    constexpr size_t SHA256_HASH_SIZE = 32;
    std::vector<unsigned char> hashBuffer(SHA256_HASH_SIZE);
    picosha2::hash256(dataStart, dataEnd, hashBuffer.begin(), hashBuffer.end());
    for (size_t byteIndex = 0; byteIndex < SHA256_HASH_SIZE; ++byteIndex) {
        digest.bytes[byteIndex] = std::byte{hashBuffer[byteIndex]};
    }
    return digest;
}

uint32_t crc32c(const std::span<const std::byte> data, const uint32_t seed) {
    if (seed != 0) {
        const uint8_t seedBytes[4] = {
            static_cast<uint8_t>(seed & 0xFFu),
            static_cast<uint8_t>((seed >> 8) & 0xFFu),
            static_cast<uint8_t>((seed >> 16) & 0xFFu),
            static_cast<uint8_t>((seed >> 24) & 0xFFu)
        };
        std::vector<uint8_t> combinedBuffer;
        combinedBuffer.reserve(4 + data.size());
        combinedBuffer.insert(combinedBuffer.end(), seedBytes, seedBytes + 4);

        const auto inputDataPointer = reinterpret_cast<const uint8_t *>(data.data());
        combinedBuffer.insert(combinedBuffer.end(), inputDataPointer, inputDataPointer + data.size());

        return CRC::Calculate(combinedBuffer.data(), combinedBuffer.size(), CRC::CRC_32_MPEG2());
    }

    const auto dataPointer = reinterpret_cast<const uint8_t *>(data.data());
    return CRC::Calculate(dataPointer, data.size(), CRC::CRC_32_MPEG2());
}

uint32_t crc32c_concat(const std::span<const std::byte> first,
                       const std::span<const std::byte> second,
                       uint32_t /*unused_seed*/) {
    std::vector<uint8_t> combinedBuffer;
    combinedBuffer.reserve(first.size() + second.size());

    const auto firstStart = reinterpret_cast<const uint8_t *>(first.data());
    combinedBuffer.insert(combinedBuffer.end(), firstStart, firstStart + first.size());

    const auto secondStart = reinterpret_cast<const uint8_t *>(second.data());
    combinedBuffer.insert(combinedBuffer.end(), secondStart, secondStart + second.size());

    return CRC::Calculate(combinedBuffer.data(), combinedBuffer.size(), CRC::CRC_32_MPEG2());
}

uint32_t packet_crc32c(std::span<const std::byte> header,
                       const std::span<const std::byte> payload,
                       const std::size_t crc_offset,
                       const std::size_t crc_size) {
    std::vector<std::byte> headerCopy(header.begin(), header.end());
    if (crc_size == 4 && crc_offset + 4 <= headerCopy.size()) {
        headerCopy[crc_offset + 0] = std::byte{0};
        headerCopy[crc_offset + 1] = std::byte{0};
        headerCopy[crc_offset + 2] = std::byte{0};
        headerCopy[crc_offset + 3] = std::byte{0};
    }

    return crc32c_concat(headerCopy, payload);
}

uint32_t read_u32_le(const std::span<const std::byte> buffer, const std::size_t byteOffset) {
    uint32_t value = 0;
    if (byteOffset + 4 <= buffer.size()) {
        std::memcpy(&value, buffer.data() + byteOffset, 4);
    }
    return value;
}

bool verify_packet_crc32c(const std::span<const std::byte> header,
                          const std::span<const std::byte> payload,
                          const std::size_t crc_offset,
                          const std::size_t crc_size) {
    if (crc_size != 4) {
        return false;
    }
    if (crc_offset + 4 > header.size()) {
        return false;
    }

    const uint32_t storedChecksum = read_u32_le(header, crc_offset);
    const uint32_t computedChecksum = packet_crc32c(header, payload, crc_offset, crc_size);
    return storedChecksum == computedChecksum;
}

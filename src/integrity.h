#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

struct Sha256Digest {
    std::array<std::byte, 32> bytes{};

    [[nodiscard]] std::string hexValue() const;

    bool operator==(const Sha256Digest & sha256) const = default;
};

uint32_t crc32c(std::span<const std::byte> data, uint32_t seed = 0);

uint32_t crc32c_concat(std::span<const std::byte> first,
                       std::span<const std::byte> second,
                       uint32_t seed = 0);

uint32_t packet_crc32c(std::span<const std::byte> header,
                       std::span<const std::byte> payload,
                       std::size_t crc_offset,
                       std::size_t crc_size = 4);

bool verify_packet_crc32c(std::span<const std::byte> header,
                          std::span<const std::byte> payload,
                          std::size_t crc_offset,
                          std::size_t crc_size = 4);

Sha256Digest sha256(std::span<const std::byte> data);

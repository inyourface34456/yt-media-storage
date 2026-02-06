#pragma once
#include <cstdint>
#include <cstdlib>
#include <string>

// Video Parameters
constexpr int FRAME_WIDTH = 3840;
constexpr int FRAME_HEIGHT = 2160;
constexpr int FRAME_FPS = 30;

const std::string VIDEO_CODEC = "ffv1";
const std::string VIDEO_CONTAINER = "mkv";

// Encoding Parameters
constexpr size_t CHUNK_SIZE_BYTES = 1024ull * 1024ull; // 1 MiB
constexpr size_t SYMBOL_SIZE_BYTES = 256;
constexpr double REPAIR_OVERHEAD = 3.00;
constexpr bool INCLUDE_SOURCE = true;
constexpr int BITS_PER_BLOCK = 1;
constexpr double COEFF_STRENGTH = 150.0;

enum Flags : uint8_t {
    None = 0,
    IsRepairSymbol = 1 << 0,
    LastChunk = 1 << 1,
};

// Header Scheme
constexpr char SHA_CHARACTERS[] = "0123456789ABCDEF";

constexpr size_t CHUNK_SIZE = 1024;

constexpr uint32_t MAGIC_ID = 0x59544653;
constexpr uint8_t VERSION_ID = 1;

constexpr size_t MAGIC_SIZE = 4;
constexpr size_t VERSION_SIZE = 1;
constexpr size_t FLAGS_SIZE = 1;
constexpr size_t FILE_ID_SIZE = 16;
constexpr size_t CHUNK_INDEX_SIZE = 4;
constexpr size_t CHUNK_SIZE_SIZE = 4;
constexpr size_t SYMBOL_SIZE_SIZE = 2;
constexpr size_t K_SIZE = 4;
constexpr size_t ESI_SIZE = 4;
constexpr size_t PAYLOAD_LEN_SIZE = 2;
constexpr size_t CRC_SIZE = 4;

constexpr size_t MAGIC_OFF = 0;
constexpr size_t VERSION_OFF = MAGIC_OFF + MAGIC_SIZE;
constexpr size_t FLAGS_OFF = VERSION_OFF + VERSION_SIZE;
constexpr size_t FILE_ID_OFF = FLAGS_OFF + FLAGS_SIZE;
constexpr size_t CHUNK_INDEX_OFF = FILE_ID_OFF + FILE_ID_SIZE;
constexpr size_t CHUNK_SIZE_OFF = CHUNK_INDEX_OFF + CHUNK_INDEX_SIZE;
constexpr size_t SYMBOL_SIZE_OFF = CHUNK_SIZE_OFF + CHUNK_SIZE_SIZE;
constexpr size_t K_OFF = SYMBOL_SIZE_OFF + SYMBOL_SIZE_SIZE;
constexpr size_t ESI_OFF = K_OFF + K_SIZE;
constexpr size_t PAYLOAD_LEN_OFF = ESI_OFF + ESI_SIZE;
constexpr size_t CRC_OFF = PAYLOAD_LEN_OFF + PAYLOAD_LEN_SIZE;
constexpr size_t HEADER_SIZE = CRC_OFF + CRC_SIZE;

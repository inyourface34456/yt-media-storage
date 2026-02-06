//
// Created by brand on 2/5/2026.
//

#include <array>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "chunker.h"
#include "configuration.h"
#include "decoder.h"
#include "encoder.h"
#include "video_encoder.h"
#include "video_decoder.h"

static std::string format_size(const std::uintmax_t bytes) {
    const char *units[] = {"B", "KB", "MB", "GB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024 && unit < 3) {
        size /= 1024;
        ++unit;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << size << " " << units[unit];
    return oss.str();
}

static std::array<std::byte, 16> make_file_id() {
    std::array<std::byte, 16> id{};
    for (int i = 0; i < 16; ++i) {
        id[i] = static_cast<std::byte>(i);
    }
    return id;
}

static void print_usage(const char *program) {
    std::cerr << "Usage:\n"
              << "  " << program << " encode --input <file> --output <video>\n"
              << "  " << program << " decode --input <video> --output <file>\n";
}

static int do_encode(const std::string &input_path, const std::string &output_path) {
    if (!std::filesystem::exists(input_path)) {
        std::cerr << "Error: input file not found: " << input_path << "\n";
        return 1;
    }

    const auto input_size = std::filesystem::file_size(input_path);
    std::cout << "Input: " << input_path << " (" << format_size(input_size) << ")\n";

    const auto chunked = chunkFile(input_path.c_str());
    std::cout << "Chunks: " << chunked.chunks.size() << "\n";

    const Encoder encoder(make_file_id());
    const std::size_t num_chunks = chunked.chunks.size();
    std::vector<Packet> packets;

    for (std::size_t i = 0; i < num_chunks; ++i) {
        const std::span<const std::byte> chunk_data = chunkSpan(chunked, i);
        const bool is_last = (i == num_chunks - 1);
        auto [chunk_packets, manifest] =
            encoder.encode_chunk(static_cast<uint32_t>(i), chunk_data, is_last);
        for (auto &pkt : chunk_packets) {
            packets.push_back(std::move(pkt));
        }
    }

    std::cout << "Packets: " << packets.size() << "\n";
    try {
        VideoEncoder video_encoder(output_path);
        video_encoder.encode_packets(packets);
        video_encoder.finalize();
    } catch (const std::exception &e) {
        std::cerr << "Error writing video: " << e.what() << "\n";
        return 1;
    }

    const auto video_size = std::filesystem::file_size(output_path);
    std::cout << "\nEncode complete: " << format_size(input_size) << " -> "
              << format_size(video_size) << "\n";
    std::cout << "Written to: " << output_path << "\n";

    return 0;
}

static int do_decode(const std::string &input_path, const std::string &output_path) {
    if (!std::filesystem::exists(input_path)) {
        std::cerr << "Error: input video not found: " << input_path << "\n";
        return 1;
    }

    const auto video_size = std::filesystem::file_size(input_path);
    std::cout << "Input: " << input_path << " (" << format_size(video_size) << ")\n";

    std::vector<Packet> packets;
    uint32_t max_chunk_index = 0;
    bool found_last_chunk = false;
    uint32_t last_chunk_index = 0;

    try {
        VideoDecoder video_decoder(input_path);
        const int64_t total = video_decoder.total_frames();
        std::cout << "Total frames: "
                  << (total >= 0 ? std::to_string(total) : "unknown") << "\n";

        std::size_t valid_frames = 0;

        while (!video_decoder.is_eof()) {
            auto frame_packets = video_decoder.decode_next_frame();
            if (!frame_packets.empty()) {
                ++valid_frames;
                for (auto &pkt_data : frame_packets) {
                    if (pkt_data.size() >= HEADER_SIZE) {
                        const auto flags =
                            static_cast<uint8_t>(pkt_data[FLAGS_OFF]);
                        uint32_t chunk_idx = 0;
                        std::memcpy(&chunk_idx,
                                    pkt_data.data() + CHUNK_INDEX_OFF,
                                    sizeof(chunk_idx));
                        if (chunk_idx > max_chunk_index)
                            max_chunk_index = chunk_idx;
                        if (flags & LastChunk) {
                            found_last_chunk = true;
                            last_chunk_index = chunk_idx;
                        }
                    }

                    Packet pkt;
                    pkt.bytes = std::move(pkt_data);
                    packets.push_back(std::move(pkt));
                }
            }
        }

        std::cout << "Valid frames: " << valid_frames << "\n";
        std::cout << "Packets extracted: " << packets.size() << "\n";
    } catch (const std::exception &e) {
        std::cerr << "Error reading video: " << e.what() << "\n";
        return 1;
    }

    if (packets.empty()) {
        std::cerr << "No packets could be extracted from the video\n";
        return 1;
    }

    uint32_t expected_chunks;
    if (found_last_chunk) {
        expected_chunks = last_chunk_index + 1;
    } else {
        expected_chunks = max_chunk_index + 1;
    }

    Decoder decoder;
    std::size_t decoded_chunks = 0;

    for (const auto &pkt : packets) {
        const std::span<const std::byte> data(pkt.bytes.data(), pkt.bytes.size());
        if (auto result = decoder.process_packet(data);
            result && result->success) {
            ++decoded_chunks;
        }
    }

    std::cout << "Chunks decoded: " << decoded_chunks << "/" << expected_chunks << "\n";

    if (decoded_chunks < expected_chunks) {
        std::cerr << "Error: only decoded " << decoded_chunks << " of "
                  << expected_chunks << " chunks\n";
        return 1;
    }

    auto assembled = decoder.assemble_file(expected_chunks);
    if (!assembled) {
        std::cerr << "Error: failed to assemble file from decoded chunks\n";
        return 1;
    }

    std::ofstream out(output_path, std::ios::binary);
    if (!out) {
        std::cerr << "Error: could not open " << output_path << " for writing\n";
        return 1;
    }

    out.write(reinterpret_cast<const char *>(assembled->data()),
              static_cast<std::streamsize>(assembled->size()));
    out.close();

    std::cout << "\nDecode complete: " << format_size(video_size) << " -> "
              << format_size(assembled->size()) << "\n";
    std::cout << "Written to: " << output_path << "\n";

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const std::string command = argv[1];

    if (command != "encode" && command != "decode") {
        std::cerr << "Error: unknown command '" << command << "'\n";
        print_usage(argv[0]);
        return 1;
    }

    std::string input_path;
    std::string output_path;

    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if ((arg == "--input" || arg == "-i") && i + 1 < argc) {
            input_path = argv[++i];
        } else if ((arg == "--output" || arg == "-o") && i + 1 < argc) {
            output_path = argv[++i];
        } else {
            std::cerr << "Error: unknown or incomplete argument '" << arg << "'\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (input_path.empty() || output_path.empty()) {
        std::cerr << "Error: both --input and --output must be specified\n";
        print_usage(argv[0]);
        return 1;
    }

    if (command == "encode") {
        return do_encode(input_path, output_path);
    } else {
        return do_decode(input_path, output_path);
    }
}

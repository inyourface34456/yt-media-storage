// This file is part of yt-media-storage, a tool for encoding media.
// Copyright (C) 2026 Brandon Li <https://brandonli.me/>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "media_storage.h"

static std::string format_size(const uint64_t bytes) {
    const char *units[] = {"B", "KB", "MB", "GB"};
    int unit = 0;
    auto size = static_cast<double>(bytes);
    while (size >= 1024 && unit < 3) {
        size /= 1024;
        ++unit;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << size << " " << units[unit];
    return oss.str();
}

static int encode_progress(const uint64_t current, const uint64_t total, void *) {
    if (total > 0) {
        std::cout << "\rEncoding chunk " << (current + 1) << "/" << total << "..." << std::flush;
    }
    return 0;
}

static int decode_progress(const uint64_t current, const uint64_t total, void *) {
    if (total > 0) {
        std::cout << "\rDecoding frame " << current << "/" << total << "..." << std::flush;
    }
    return 0;
}

static int stream_encode_progress(const uint64_t current, const uint64_t total, void *) {
    if (total > 0) {
        std::cout << "\rStreaming chunk " << (current + 1) << "/" << total << "..." << std::flush;
    }
    return 0;
}

static int stream_decode_progress(const uint64_t current, const uint64_t total, void *) {
    if (total > 0) {
        std::cout << "\rReceiving frame " << current << "/" << total << "..." << std::flush;
    } else {
        std::cout << "\rReceiving frame " << current << "..." << std::flush;
    }
    return 0;
}

static void print_usage(const char *program) {
    std::cerr << "Usage:\n"
            << "  " << program <<
            " encode --input <file> --output <video> [--encrypt --password <pwd>] [--hash <crc32|xxhash>]\n"
            << "  " << program << " decode --input <video> --output <file> [--password <pwd>]\n"
            << "  " << program <<
            " stream-encode --input <file> --url <rtmp://...> [--bitrate <kbps>] [--width <w> --height <h>] [--encrypt --password <pwd>]\n"
            << "  " << program << " stream-decode --url <stream_url> --output <file> [--password <pwd>]\n";
}

static int do_encode(const std::string &input_path, const std::string &output_path,
                     const bool encrypt, const std::string &password,
                     const ms_hash_algorithm_t hash_algo) {
    std::cout << "Input: " << input_path << "\n";
    std::cout << "Output: " << output_path << "\n";

    ms_encode_options_t opts{};
    opts.input_path = input_path.c_str();
    opts.output_path = output_path.c_str();
    opts.encrypt = encrypt ? 1 : 0;
    opts.password = password.c_str();
    opts.password_len = password.size();
    opts.hash_algorithm = hash_algo;
    opts.progress = encode_progress;
    opts.progress_user = nullptr;

    ms_result_t result{};
    if (const ms_status_t status = ms_encode(&opts, &result); status != MS_OK) {
        std::cout << "\n";
        std::cerr << "Error: " << ms_status_string(status) << "\n";
        return 1;
    }

    std::cout << "\n\nEncode complete: " << format_size(result.input_size) << " -> "
            << format_size(result.output_size) << "\n";
    std::cout << "Chunks: " << result.total_chunks
            << "  Packets: " << result.total_packets
            << "  Frames: " << result.total_frames << "\n";
    std::cout << "Written to: " << output_path << "\n";

    return 0;
}

static int do_decode(const std::string &input_path, const std::string &output_path,
                     const std::string &password) {
    std::cout << "Input: " << input_path << "\n";
    std::cout << "Output: " << output_path << "\n";

    ms_decode_options_t opts{};
    opts.input_path = input_path.c_str();
    opts.output_path = output_path.c_str();
    opts.password = password.c_str();
    opts.password_len = password.size();
    opts.progress = decode_progress;
    opts.progress_user = nullptr;

    ms_result_t result{};
    if (const ms_status_t status = ms_decode(&opts, &result); status != MS_OK) {
        std::cout << "\n";
        std::cerr << "Error: " << ms_status_string(status) << "\n";
        return 1;
    }

    std::cout << "\n\nDecode complete: " << format_size(result.input_size) << " -> "
            << format_size(result.output_size) << "\n";
    std::cout << "Chunks: " << result.total_chunks
            << "  Packets: " << result.total_packets
            << "  Frames: " << result.total_frames << "\n";
    std::cout << "Written to: " << output_path << "\n";

    return 0;
}

static int do_stream_encode(const std::string &input_path, const std::string &stream_url,
                            const bool encrypt, const std::string &password,
                            const ms_hash_algorithm_t hash_algo, const int bitrate_kbps,
                            const int width, const int height) {
    std::cout << "Input: " << input_path << "\n";
    std::cout << "Stream URL: " << stream_url << "\n";
    std::cout << "Resolution: " << width << "x" << height << "\n";
    std::cout << "Bitrate: " << bitrate_kbps << " kbps\n";

    ms_stream_encode_options_t opts{};
    opts.input_path = input_path.c_str();
    opts.stream_url = stream_url.c_str();
    opts.encrypt = encrypt ? 1 : 0;
    opts.password = password.c_str();
    opts.password_len = password.size();
    opts.hash_algorithm = hash_algo;
    opts.bitrate_kbps = bitrate_kbps;
    opts.width = width;
    opts.height = height;
    opts.progress = stream_encode_progress;
    opts.progress_user = nullptr;

    ms_result_t result{};
    if (const ms_status_t status = ms_stream_encode(&opts, &result); status != MS_OK) {
        std::cout << "\n";
        std::cerr << "Error: " << ms_status_string(status) << "\n";
        return 1;
    }

    std::cout << "\n\nStream encode complete: " << format_size(result.input_size) << "\n";
    std::cout << "Chunks: " << result.total_chunks
            << "  Packets: " << result.total_packets
            << "  Frames: " << result.total_frames << "\n";

    return 0;
}

static int do_stream_decode(const std::string &stream_url, const std::string &output_path,
                            const std::string &password) {
    std::cout << "Stream URL: " << stream_url << "\n";
    std::cout << "Output: " << output_path << "\n";
    std::cout << "Waiting for stream...\n";

    ms_stream_decode_options_t opts{};
    opts.stream_url = stream_url.c_str();
    opts.output_path = output_path.c_str();
    opts.password = password.c_str();
    opts.password_len = password.size();
    opts.timeout_sec = 30;
    opts.progress = stream_decode_progress;
    opts.progress_user = nullptr;

    ms_result_t result{};
    if (const ms_status_t status = ms_stream_decode(&opts, &result); status != MS_OK) {
        std::cout << "\n";
        std::cerr << "Error: " << ms_status_string(status) << "\n";
        return 1;
    }

    std::cout << "\n\nStream decode complete: -> " << format_size(result.output_size) << "\n";
    std::cout << "Chunks: " << result.total_chunks
            << "  Packets: " << result.total_packets
            << "  Frames: " << result.total_frames << "\n";
    std::cout << "Written to: " << output_path << "\n";

    return 0;
}

int main(const int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const std::string command = argv[1];

    if (command != "encode" && command != "decode" &&
        command != "stream-encode" && command != "stream-decode") {
        std::cerr << "Error: unknown command '" << command << "'\n";
        print_usage(argv[0]);
        return 1;
    }

    std::string input_path;
    std::string output_path;
    std::string stream_url;
    bool encrypt = false;
    std::string password;
    auto hash_algo = MS_HASH_CRC32;
    int bitrate_kbps = 35000;
    int stream_width = 1920;
    int stream_height = 1080;

    for (int i = 2; i < argc; ++i) {
        if (const std::string arg = argv[i]; (arg == "--input" || arg == "-i") && i + 1 < argc) {
            input_path = argv[++i];
        } else if ((arg == "--output" || arg == "-o") && i + 1 < argc) {
            output_path = argv[++i];
        } else if ((arg == "--url" || arg == "-u") && i + 1 < argc) {
            stream_url = argv[++i];
        } else if ((arg == "--bitrate" || arg == "-b") && i + 1 < argc) {
            bitrate_kbps = std::stoi(argv[++i]);
        } else if (arg == "--width" && i + 1 < argc) {
            stream_width = std::stoi(argv[++i]);
        } else if (arg == "--height" && i + 1 < argc) {
            stream_height = std::stoi(argv[++i]);
        } else if ((arg == "--encrypt" || arg == "-e")) {
            encrypt = true;
        } else if ((arg == "--password" || arg == "-p") && i + 1 < argc) {
            password = argv[++i];
        } else if ((arg == "--hash" || arg == "-H") && i + 1 < argc) {
            if (const std::string algo_str = argv[++i]; algo_str == "xxhash") {
                hash_algo = MS_HASH_XXHASH32;
            } else if (algo_str == "crc32") {
                hash_algo = MS_HASH_CRC32;
            } else {
                std::cerr << "Error: unknown hash algorithm '" << algo_str << "' (use crc32 or xxhash)\n";
                return 1;
            }
        } else {
            std::cerr << "Error: unknown or incomplete argument '" << arg << "'\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (command == "encode") {
        if (input_path.empty() || output_path.empty()) {
            std::cerr << "Error: both --input and --output must be specified\n";
            print_usage(argv[0]);
            return 1;
        }
        if (encrypt && password.empty()) {
            std::cerr << "Error: --encrypt requires --password\n";
            return 1;
        }
        return do_encode(input_path, output_path, encrypt, password, hash_algo);
    } else if (command == "decode") {
        if (input_path.empty() || output_path.empty()) {
            std::cerr << "Error: both --input and --output must be specified\n";
            print_usage(argv[0]);
            return 1;
        }
        return do_decode(input_path, output_path, password);
    } else if (command == "stream-encode") {
        if (input_path.empty() || stream_url.empty()) {
            std::cerr << "Error: --input and --url must be specified for stream-encode\n";
            print_usage(argv[0]);
            return 1;
        }
        if (encrypt && password.empty()) {
            std::cerr << "Error: --encrypt requires --password\n";
            return 1;
        }
        return do_stream_encode(input_path, stream_url, encrypt, password, hash_algo, bitrate_kbps,
                                stream_width, stream_height);
    } else {
        if (stream_url.empty() || output_path.empty()) {
            std::cerr << "Error: --url and --output must be specified for stream-decode\n";
            print_usage(argv[0]);
            return 1;
        }
        return do_stream_decode(stream_url, output_path, password);
    }
}

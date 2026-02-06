#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/imgutils.h>
#include <libavutil/opt.h>
#include <libswscale/swscale.h>
}

#include "encoder.h"

struct FrameLayout {
    int frame_width;
    int frame_height;
    int blocks_per_row;
    int blocks_per_col;
    int total_blocks;
    int bits_per_frame;
    int bytes_per_frame;
};

FrameLayout compute_frame_layout();

std::size_t max_packet_bytes_per_frame();

class VideoEncoder {
public:
    explicit VideoEncoder(const std::string &output_path);

    ~VideoEncoder();

    VideoEncoder(const VideoEncoder &) = delete;

    VideoEncoder &operator=(const VideoEncoder &) = delete;

    VideoEncoder(VideoEncoder &&) = delete;

    VideoEncoder &operator=(VideoEncoder &&) = delete;

    void add_packet(const Packet &packet);

    void encode_packets(const std::vector<Packet> &packets);

    void finalize();

    [[nodiscard]] int64_t frames_written() const { return frame_index; }

    [[nodiscard]] static int packets_per_frame();

private:
    AVFormatContext *format_ctx = nullptr;
    AVCodecContext *codec_ctx = nullptr;
    AVStream *stream = nullptr;
    AVFrame *frame = nullptr;
    AVPacket *av_packet = nullptr;
    SwsContext *sws_ctx = nullptr;

    std::vector<uint8_t> gray_buffer;
    std::vector<std::byte> frame_data_buffer;
    int64_t frame_index = 0;
    bool finalized = false;

    void init_encoder(const std::string &output_path);

    void embed_data_in_frame(const std::vector<std::byte> &data);

    void encode_frame();

    void flush_encoder() const;

    void flush_frame_buffer();
};

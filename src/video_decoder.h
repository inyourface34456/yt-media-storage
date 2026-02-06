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

class VideoDecoder {
public:
    explicit VideoDecoder(const std::string &input_path);
    ~VideoDecoder();

    VideoDecoder(const VideoDecoder &) = delete;
    VideoDecoder &operator=(const VideoDecoder &) = delete;
    VideoDecoder(VideoDecoder &&) = delete;
    VideoDecoder &operator=(VideoDecoder &&) = delete;

    std::vector<std::vector<std::byte>> decode_next_frame();
    std::vector<std::vector<std::byte>> decode_all_frames();

    [[nodiscard]] int64_t frames_read() const { return frame_index_; }
    [[nodiscard]] int64_t total_frames() const;
    [[nodiscard]] bool is_eof() const { return eof_; }

private:
    AVFormatContext *format_ctx_ = nullptr;
    AVCodecContext *codec_ctx_ = nullptr;
    AVFrame *frame_ = nullptr;
    AVFrame *gray_frame_ = nullptr;
    AVPacket *av_packet_ = nullptr;
    SwsContext *sws_ctx_ = nullptr;

    int video_stream_index_ = -1;
    int64_t frame_index_ = 0;
    bool eof_ = false;

    std::vector<uint8_t> gray_buffer_;

    void init_decoder(const std::string &input_path);
    std::vector<std::byte> extract_data_from_frame() const;
    std::vector<std::vector<std::byte>> extract_packets_from_frame() const;
};

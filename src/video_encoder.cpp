#include "video_encoder.h"
#include "configuration.h"

#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>

constexpr double PI = 3.14159265358979323846;

static const auto &get_cosine_table() {
    static std::array<std::array<double, 8>, 8> table = [] {
        std::array<std::array<double, 8>, 8> t{};
        for (int i = 0; i < 8; ++i) {
            for (int j = 0; j < 8; ++j) {
                t[i][j] = std::cos((2.0 * i + 1.0) * j * PI / 16.0);
            }
        }
        return t;
    }();
    return table;
}

static double alpha(int u) {
    return u == 0 ? 1.0 / std::sqrt(2.0) : 1.0;
}

static void forward_dct_8x8(const double input[8][8], double output[8][8]) {
    const auto &cos_table = get_cosine_table();
    for (int u = 0; u < 8; ++u) {
        for (int v = 0; v < 8; ++v) {
            double sum = 0.0;
            for (int x = 0; x < 8; ++x) {
                for (int y = 0; y < 8; ++y) {
                    sum += input[x][y] * cos_table[x][u] * cos_table[y][v];
                }
            }
            output[u][v] = 0.25 * alpha(u) * alpha(v) * sum;
        }
    }
}

static void inverse_dct_8x8(const double input[8][8], double output[8][8]) {
    const auto &cos_table = get_cosine_table();
    for (int x = 0; x < 8; ++x) {
        for (int y = 0; y < 8; ++y) {
            double sum = 0.0;
            for (int u = 0; u < 8; ++u) {
                for (int v = 0; v < 8; ++v) {
                    sum += alpha(u) * alpha(v) * input[u][v]
                            * cos_table[x][u] * cos_table[y][v];
                }
            }
            output[x][y] = 0.25 * sum;
        }
    }
}

static constexpr std::pair<int, int> EMBED_POSITIONS[] = {
    {0, 1},
    {1, 0},
    {1, 1},
    {0, 2},
};

static_assert(BITS_PER_BLOCK <= 4, "Max 4 bits per block");

FrameLayout compute_frame_layout() {
    FrameLayout layout{};
    layout.frame_width = FRAME_WIDTH;
    layout.frame_height = FRAME_HEIGHT;
    layout.blocks_per_row = FRAME_WIDTH / 8;
    layout.blocks_per_col = FRAME_HEIGHT / 8;
    layout.total_blocks = layout.blocks_per_row * layout.blocks_per_col;
    layout.bits_per_frame = layout.total_blocks * BITS_PER_BLOCK;
    layout.bytes_per_frame = layout.bits_per_frame / 8;
    return layout;
}

std::size_t max_packet_bytes_per_frame() {
    return static_cast<std::size_t>(compute_frame_layout().bytes_per_frame);
}

VideoEncoder::VideoEncoder(const std::string &output_path) {
    init_encoder(output_path);
}

VideoEncoder::~VideoEncoder() {
    if (!finalized) {
        try { finalize(); } catch (...) {
        }
    }
    if (sws_ctx) sws_free_context(&sws_ctx);
    if (av_packet) av_packet_free(&av_packet);
    if (frame) av_frame_free(&frame);
    if (codec_ctx) avcodec_free_context(&codec_ctx);
    if (format_ctx) {
        if (format_ctx->pb) avio_closep(&format_ctx->pb);
        avformat_free_context(format_ctx);
    }
}

void VideoEncoder::init_encoder(const std::string &output_path) {
    int ret = avformat_alloc_output_context2(&format_ctx, nullptr, nullptr, output_path.c_str());
    if (ret < 0 || !format_ctx) {
        throw std::runtime_error("Failed to create output context");
    }

    const AVCodec *codec = avcodec_find_encoder_by_name(VIDEO_CODEC.c_str());
    if (!codec) {
        throw std::runtime_error("Failed to find encoder: " + VIDEO_CODEC);
    }

    stream = avformat_new_stream(format_ctx, nullptr);
    if (!stream) {
        throw std::runtime_error("Failed to create stream");
    }

    codec_ctx = avcodec_alloc_context3(codec);
    if (!codec_ctx) {
        throw std::runtime_error("Failed to allocate codec context");
    }

    codec_ctx->width = FRAME_WIDTH;
    codec_ctx->height = FRAME_HEIGHT;
    codec_ctx->time_base = {1, FRAME_FPS};
    codec_ctx->framerate = {FRAME_FPS, 1};
    codec_ctx->gop_size = 30;
    codec_ctx->max_b_frames = 0;
    if (VIDEO_CODEC == "libx264") {
        codec_ctx->pix_fmt = AV_PIX_FMT_YUV444P;
        av_opt_set(codec_ctx->priv_data, "preset", "ultrafast", 0);
        av_opt_set(codec_ctx->priv_data, "crf", "0", 0); // Lossless
    } else if (VIDEO_CODEC == "libx265") {
        codec_ctx->pix_fmt = AV_PIX_FMT_GRAY8;
        av_opt_set(codec_ctx->priv_data, "preset", "ultrafast", 0);
        av_opt_set(codec_ctx->priv_data, "x265-params", "lossless=1", 0);
    } else if (VIDEO_CODEC == "ffv1") {
        codec_ctx->pix_fmt = AV_PIX_FMT_GRAY8;
    } else {
        codec_ctx->pix_fmt = AV_PIX_FMT_YUV420P;
    }

    if (codec->pix_fmts) {
        bool format_supported = false;
        for (const AVPixelFormat *p = codec->pix_fmts; *p != AV_PIX_FMT_NONE; ++p) {
            if (*p == codec_ctx->pix_fmt) {
                format_supported = true;
                break;
            }
        }
        if (!format_supported) {
            codec_ctx->pix_fmt = codec->pix_fmts[0];
            std::cerr << "[VideoEncoder] Requested format not supported, using: "
                    << codec_ctx->pix_fmt << "\n";
        }
    }

    if (format_ctx->oformat->flags & AVFMT_GLOBALHEADER) {
        codec_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
    }

    ret = avcodec_open2(codec_ctx, codec, nullptr);
    if (ret < 0) {
        char error_buffer[256];
        av_strerror(ret, error_buffer, sizeof(error_buffer));
        throw std::runtime_error(std::string("Failed to open codec: ") + error_buffer);
    }

    ret = avcodec_parameters_from_context(stream->codecpar, codec_ctx);
    if (ret < 0) {
        throw std::runtime_error("Failed to copy codec parameters");
    }

    stream->time_base = codec_ctx->time_base;

    frame = av_frame_alloc();
    if (!frame) {
        throw std::runtime_error("Failed to allocate frame");
    }

    frame->format = codec_ctx->pix_fmt;
    frame->width = codec_ctx->width;
    frame->height = codec_ctx->height;

    ret = av_frame_get_buffer(frame, 0);
    if (ret < 0) {
        throw std::runtime_error("Failed to allocate frame buffer");
    }

    av_packet = av_packet_alloc();
    if (!av_packet) {
        throw std::runtime_error("Failed to allocate packet");
    }

    gray_buffer.resize(static_cast<std::size_t>(FRAME_WIDTH) * FRAME_HEIGHT);
    if (codec_ctx->pix_fmt != AV_PIX_FMT_GRAY8) {
        sws_ctx = sws_getContext(
            FRAME_WIDTH, FRAME_HEIGHT, AV_PIX_FMT_GRAY8,
            FRAME_WIDTH, FRAME_HEIGHT, codec_ctx->pix_fmt,
            SWS_POINT, nullptr, nullptr, nullptr
        );
        if (!sws_ctx) {
            throw std::runtime_error("Failed to create swscale context");
        }
    }

    ret = avio_open(&format_ctx->pb, output_path.c_str(), AVIO_FLAG_WRITE);
    if (ret < 0) {
        throw std::runtime_error("Failed to open output file");
    }

    ret = avformat_write_header(format_ctx, nullptr);
    if (ret < 0) {
        throw std::runtime_error("Failed to write header");
    }
}

int VideoEncoder::packets_per_frame() {
    const auto layout = compute_frame_layout();
    constexpr std::size_t packet_size = HEADER_SIZE + SYMBOL_SIZE_BYTES;
    return static_cast<int>(layout.bytes_per_frame / packet_size);
}

void VideoEncoder::embed_data_in_frame(const std::vector<std::byte> &data) {
    const auto layout = compute_frame_layout();
    std::ranges::fill(gray_buffer, 128);
    std::size_t bit_index = 0;
    const std::size_t total_bits = data.size() * 8;
    for (int block_row = 0; block_row < layout.blocks_per_col && bit_index < total_bits; ++block_row) {
        for (int block_col = 0; block_col < layout.blocks_per_row && bit_index < total_bits; ++block_col) {
            double block[8][8];
            const int base_x = block_col * 8;
            const int base_y = block_row * 8;

            for (int y = 0; y < 8; ++y) {
                for (int x = 0; x < 8; ++x) {
                    block[y][x] = static_cast<double>(gray_buffer[(base_y + y) * FRAME_WIDTH + base_x + x]);
                }
            }

            double dct[8][8];
            forward_dct_8x8(block, dct);

            for (int b = 0; b < BITS_PER_BLOCK && bit_index < total_bits; ++b) {
                const std::size_t byte_idx = bit_index / 8;
                const std::size_t bit_pos = 7 - (bit_index % 8);
                const int bit = (static_cast<uint8_t>(data[byte_idx]) >> bit_pos) & 1;
                const auto [coef_y, coef_x] = EMBED_POSITIONS[b];
                dct[coef_y][coef_x] = bit ? COEFF_STRENGTH : -COEFF_STRENGTH;
                ++bit_index;
            }

            double reconstructed[8][8];
            inverse_dct_8x8(dct, reconstructed);
            for (int y = 0; y < 8; ++y) {
                for (int x = 0; x < 8; ++x) {
                    double val = reconstructed[y][x];
                    val = std::clamp(val, 0.0, 255.0);
                    gray_buffer[(base_y + y) * FRAME_WIDTH + base_x + x] = static_cast<uint8_t>(val);
                }
            }
        }
    }

    if (sws_ctx) {
        const uint8_t *src_data[1] = {gray_buffer.data()};
        constexpr int src_linesize[1] = {FRAME_WIDTH};
        sws_scale(sws_ctx, src_data, src_linesize, 0, FRAME_HEIGHT,
                  frame->data, frame->linesize);
    } else {
        for (int y = 0; y < FRAME_HEIGHT; ++y) {
            std::memcpy(frame->data[0] + y * frame->linesize[0],
                        gray_buffer.data() + y * FRAME_WIDTH,
                        FRAME_WIDTH);
        }
    }
}

void VideoEncoder::encode_frame() {
    int ret = av_frame_make_writable(frame);
    if (ret < 0) {
        throw std::runtime_error("Frame not writable");
    }

    frame->pts = frame_index++;

    ret = avcodec_send_frame(codec_ctx, frame);
    if (ret < 0) {
        throw std::runtime_error("Error sending frame");
    }

    while (ret >= 0) {
        ret = avcodec_receive_packet(codec_ctx, av_packet);
        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {
            break;
        }
        if (ret < 0) {
            throw std::runtime_error("Error receiving packet");
        }

        av_packet_rescale_ts(av_packet, codec_ctx->time_base, stream->time_base);
        av_packet->stream_index = stream->index;

        ret = av_interleaved_write_frame(format_ctx, av_packet);
        if (ret < 0) {
            throw std::runtime_error("Error writing frame");
        }

        av_packet_unref(av_packet);
    }
}

void VideoEncoder::add_packet(const Packet &packet) {
    if (finalized) {
        throw std::runtime_error("Encoder already finalized");
    }

    const auto layout = compute_frame_layout();
    if (const std::size_t max_bytes = static_cast<std::size_t>(layout.bytes_per_frame);
        frame_data_buffer.size() + packet.bytes.size() > max_bytes) {
        flush_frame_buffer();
    }

    frame_data_buffer.insert(frame_data_buffer.end(),
                              packet.bytes.begin(),
                              packet.bytes.end());
}

void VideoEncoder::encode_packets(const std::vector<Packet> &packets) {
    for (const auto &pkt: packets) {
        add_packet(pkt);
    }
}

void VideoEncoder::flush_frame_buffer() {
    if (frame_data_buffer.empty()) return;

    embed_data_in_frame(frame_data_buffer);
    encode_frame();
    frame_data_buffer.clear();
}

void VideoEncoder::flush_encoder() const {
    int ret = avcodec_send_frame(codec_ctx, nullptr);

    while (ret >= 0) {
        ret = avcodec_receive_packet(codec_ctx, av_packet);
        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {
            break;
        }
        if (ret < 0) {
            throw std::runtime_error("Error flushing encoder");
        }

        av_packet_rescale_ts(av_packet, codec_ctx->time_base, stream->time_base);
        av_packet->stream_index = stream->index;

        av_interleaved_write_frame(format_ctx, av_packet);
        av_packet_unref(av_packet);
    }
}

void VideoEncoder::finalize() {
    if (finalized) return;
    finalized = true;
    flush_frame_buffer();
    flush_encoder();
    av_write_trailer(format_ctx);
}

#include <gtest/gtest.h>

#include "crypto.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace {

std::array<std::byte, 16> make_file_id() {
    std::array<std::byte, 16> id{};
    for (std::size_t i = 0; i < 16; ++i) {
        id[i] = static_cast<std::byte>(i);
    }
    return id;
}

std::array<std::byte, CRYPTO_KEY_BYTES> make_key() {
    static constexpr std::byte password[] = {
        std::byte{'t'}, std::byte{'e'}, std::byte{'s'}, std::byte{'t'},
        std::byte{'p'}, std::byte{'a'}, std::byte{'s'}, std::byte{'s'},
    };
    std::array<std::byte, 16> salt{};
    for (std::size_t i = 0; i < 16; ++i) {
        salt[i] = static_cast<std::byte>(0x10 + i);
    }
    return derive_key(std::span(password), salt);
}

} // namespace

TEST(CryptoTest, DeriveKey_Deterministic) {
    static constexpr std::byte password[] = {std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
    std::array<std::byte, 16> salt{};
    for (std::size_t i = 0; i < 16; ++i) {
        salt[i] = static_cast<std::byte>(i);
    }
    const auto k1 = derive_key(std::span(password), salt);
    const auto k2 = derive_key(std::span(password), salt);
    EXPECT_EQ(k1, k2);
}

TEST(CryptoTest, DeriveKey_DifferentPasswords) {
    static constexpr std::byte pw1[] = {std::byte{'a'}};
    static constexpr std::byte pw2[] = {std::byte{'b'}};
    std::array<std::byte, 16> salt{};
    for (std::size_t i = 0; i < 16; ++i) {
        salt[i] = static_cast<std::byte>(0x20 + i);
    }
    const auto k1 = derive_key(std::span(pw1), salt);
    const auto k2 = derive_key(std::span(pw2), salt);
    EXPECT_NE(k1, k2);
}

TEST(CryptoTest, DeriveKey_DifferentSalts) {
    static constexpr std::byte password[] = {std::byte{'x'}, std::byte{'y'}};
    std::array<std::byte, 16> salt1{};
    std::array<std::byte, 16> salt2{};
    for (std::size_t i = 0; i < 16; ++i) {
        salt1[i] = static_cast<std::byte>(i);
        salt2[i] = static_cast<std::byte>(0xFF - i);
    }
    const auto k1 = derive_key(std::span(password), salt1);
    const auto k2 = derive_key(std::span(password), salt2);
    EXPECT_NE(k1, k2);
}

TEST(CryptoTest, EncryptDecrypt_Roundtrip) {
    const auto key = make_key();
    const auto file_id = make_file_id();
    std::vector<std::byte> plain(64);
    for (std::size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<std::byte>(i * 3u);
    }
    const auto enc = encrypt_chunk(plain, key, file_id, 0u);
    const auto dec = decrypt_chunk(enc, key, file_id, 0u);
    EXPECT_EQ(dec, plain);
}

TEST(CryptoTest, EncryptDecrypt_SmallData) {
    const auto key = make_key();
    const auto file_id = make_file_id();
    std::vector plain{std::byte{0x42}};
    const auto enc = encrypt_chunk(plain, key, file_id, 0u);
    const auto dec = decrypt_chunk(enc, key, file_id, 0u);
    EXPECT_EQ(dec, plain);
}

TEST(CryptoTest, EncryptDecrypt_LargeData) {
    const auto key = make_key();
    const auto file_id = make_file_id();
    constexpr std::size_t n = 100u * 1024u;
    std::vector<std::byte> plain(n);
    for (std::size_t i = 0; i < n; ++i) {
        plain[i] = static_cast<std::byte>(static_cast<unsigned char>(i & 0xFF));
    }
    const auto enc = encrypt_chunk(plain, key, file_id, 7u);
    const auto dec = decrypt_chunk(enc, key, file_id, 7u);
    EXPECT_EQ(dec, plain);
}

TEST(CryptoTest, DecryptChunkInto_Roundtrip) {
    const auto key = make_key();
    const auto file_id = make_file_id();
    std::vector<std::byte> plain(128);
    for (std::size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<std::byte>(0xA0 + (i % 16));
    }
    const auto enc = encrypt_chunk(plain, key, file_id, 3u);
    std::vector<std::byte> out(plain.size());
    decrypt_chunk_into(out, enc, key, file_id, 3u);
    EXPECT_EQ(out, plain);
}

TEST(CryptoTest, EncryptedSize_IncludesOverhead) {
    const auto key = make_key();
    const auto file_id = make_file_id();
    std::vector<std::byte> plain(500);
    for (std::size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<std::byte>(i & 0xFF);
    }
    const auto enc = encrypt_chunk(plain, key, file_id, 0u);
    EXPECT_EQ(enc.size(), plain.size() + CRYPTO_PLAIN_SIZE_HEADER + 16u);
}

TEST(CryptoTest, Decrypt_WrongKey_Throws) {
    const auto key = make_key();
    const auto file_id = make_file_id();
    std::vector plain{std::byte{1}, std::byte{2}, std::byte{3}};
    const auto enc = encrypt_chunk(plain, key, file_id, 0u);

    std::array<std::byte, CRYPTO_KEY_BYTES> wrong_key = key;
    wrong_key[0] ^= std::byte{1};

    EXPECT_THROW(decrypt_chunk(enc, wrong_key, file_id, 0u), std::runtime_error);
}

TEST(CryptoTest, Decrypt_WrongChunkIndex_Throws) {
    const auto key = make_key();
    const auto file_id = make_file_id();
    std::vector<std::byte> plain(32);
    for (std::size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<std::byte>(i);
    }
    const auto enc = encrypt_chunk(plain, key, file_id, 5u);
    EXPECT_THROW(decrypt_chunk(enc, key, file_id, 6u), std::runtime_error);
}

TEST(CryptoTest, ReadPlainSizeFromHeader) {
    std::array<std::byte, 4> hdr{};
    constexpr uint32_t v = 0xDEADBEEFu;
    hdr[0] = static_cast<std::byte>(v & 0xFFu);
    hdr[1] = static_cast<std::byte>((v >> 8) & 0xFFu);
    hdr[2] = static_cast<std::byte>((v >> 16) & 0xFFu);
    hdr[3] = static_cast<std::byte>((v >> 24) & 0xFFu);
    EXPECT_EQ(read_plain_size_from_header(hdr), v);
}

TEST(CryptoTest, SecureZero_ClearsBuffer) {
    std::vector<std::byte> buf(64);
    for (auto &b : buf) {
        b = std::byte{0xFF};
    }
    secure_zero(buf);
    for (const auto b : buf) {
        EXPECT_EQ(b, std::byte{0});
    }
}

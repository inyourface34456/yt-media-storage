#include "crypto.h"
#include "configuration.h"

#include <sodium.h>
#include <cstring>
#include <mutex>
#include <stdexcept>

static std::once_flag sodium_init_flag;

static void ensure_sodium_init() {
    std::call_once(sodium_init_flag, [] {
        if (sodium_init() < 0) {
            throw std::runtime_error("sodium_init failed");
        }
    });
}

std::array<std::byte, CRYPTO_KEY_BYTES> derive_key(
    std::span<const std::byte> password,
    std::span<const std::byte, 16> salt) {
    ensure_sodium_init();

    std::array<std::byte, CRYPTO_KEY_BYTES> key{};
    if (crypto_pwhash(
            reinterpret_cast<unsigned char*>(key.data()),
            key.size(),
            reinterpret_cast<const char*>(password.data()),
            password.size(),
            reinterpret_cast<const unsigned char*>(salt.data()),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("Key derivation failed");
    }
    return key;
}

static void build_nonce(
    std::span<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce,
    std::span<const std::byte, 16> file_id,
    uint32_t chunk_index) {
    std::memcpy(nonce.data(), file_id.data(), 16);
    nonce[16] = static_cast<unsigned char>(chunk_index & 0xff);
    nonce[17] = static_cast<unsigned char>((chunk_index >> 8) & 0xff);
    nonce[18] = static_cast<unsigned char>((chunk_index >> 16) & 0xff);
    nonce[19] = static_cast<unsigned char>((chunk_index >> 24) & 0xff);
    std::memset(nonce.data() + 20, 0, 4);
}

std::vector<std::byte> encrypt_chunk(
    std::span<const std::byte> plain,
    std::span<const std::byte, CRYPTO_KEY_BYTES> key,
    std::span<const std::byte, 16> file_id,
    uint32_t chunk_index) {
    ensure_sodium_init();

    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce{};
    build_nonce(nonce, file_id, chunk_index);

    const std::size_t cipher_len = plain.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    std::vector<std::byte> cipher(cipher_len);

    unsigned long long written = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            reinterpret_cast<unsigned char*>(cipher.data()),
            &written,
            reinterpret_cast<const unsigned char*>(plain.data()),
            plain.size(),
            nullptr,
            0,
            nullptr,
            nonce.data(),
            reinterpret_cast<const unsigned char*>(key.data())) != 0) {
        throw std::runtime_error("Encryption failed");
    }

    cipher.resize(static_cast<std::size_t>(written));

    std::vector<std::byte> result;
    result.reserve(CRYPTO_PLAIN_SIZE_HEADER + cipher.size());
    const uint32_t plain_size_le = static_cast<uint32_t>(plain.size());
    result.push_back(std::byte(plain_size_le & 0xff));
    result.push_back(std::byte((plain_size_le >> 8) & 0xff));
    result.push_back(std::byte((plain_size_le >> 16) & 0xff));
    result.push_back(std::byte((plain_size_le >> 24) & 0xff));
    result.insert(result.end(), cipher.begin(), cipher.end());
    return result;
}

std::vector<std::byte> decrypt_chunk(
    std::span<const std::byte> chunk_from_decoder,
    std::span<const std::byte, CRYPTO_KEY_BYTES> key,
    std::span<const std::byte, 16> file_id,
    uint32_t chunk_index) {
    ensure_sodium_init();

    if (chunk_from_decoder.size() < CRYPTO_PLAIN_SIZE_HEADER) {
        throw std::runtime_error("Decryption failed (chunk too small)");
    }

    uint32_t plain_size = 0;
    plain_size |= static_cast<uint32_t>(static_cast<uint8_t>(chunk_from_decoder[0]));
    plain_size |= static_cast<uint32_t>(static_cast<uint8_t>(chunk_from_decoder[1])) << 8;
    plain_size |= static_cast<uint32_t>(static_cast<uint8_t>(chunk_from_decoder[2])) << 16;
    plain_size |= static_cast<uint32_t>(static_cast<uint8_t>(chunk_from_decoder[3])) << 24;

    const std::size_t cipher_len = plain_size + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (plain_size > CHUNK_SIZE_BYTES ||
        chunk_from_decoder.size() < CRYPTO_PLAIN_SIZE_HEADER + cipher_len) {
        throw std::runtime_error("Decryption failed (wrong password or corrupted data)");
    }

    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce{};
    build_nonce(nonce, file_id, chunk_index);

    std::vector<std::byte> plain(cipher_len);

    unsigned long long written = 0;
    const auto cipher_span = chunk_from_decoder.subspan(CRYPTO_PLAIN_SIZE_HEADER, cipher_len);
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(plain.data()),
            &written,
            nullptr,
            reinterpret_cast<const unsigned char*>(cipher_span.data()),
            cipher_span.size(),
            nullptr,
            0,
            nonce.data(),
            reinterpret_cast<const unsigned char*>(key.data())) != 0) {
        throw std::runtime_error("Decryption failed (wrong password or corrupted data)");
    }

    plain.resize(static_cast<std::size_t>(written));
    return plain;
}

void secure_zero(std::span<std::byte> data) {
    if (!data.empty()) {
        sodium_memzero(data.data(), data.size());
    }
}

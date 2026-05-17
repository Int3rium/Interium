#ifndef INTERIUM_CRYPTO_H
#define INTERIUM_CRYPTO_H

#include "types.h"
#include <vector>

namespace Interium {

enum class ObfuscationLevel {
    LOW,
    MID,
    HIGH
};

class Crypto {
public:
    static std::vector<u8> encrypt(const std::vector<u8>& data, const std::vector<u8>& key, ObfuscationLevel level);
    static std::vector<u8> decrypt(const u8* data, size_t size, const u8* key, size_t keySize, ObfuscationLevel level);

    static std::vector<u8> g_Key(size_t length);
    static std::vector<u8> x_Crypt(const std::vector<u8>& data, const std::vector<u8>& key);

    static std::vector<u8> a_Enc(const std::vector<u8>& data, const std::vector<u8>& key);
    static std::vector<u8> a_Dec(const u8* data, size_t size, const u8* key);
};

} // namespace Interium

#endif

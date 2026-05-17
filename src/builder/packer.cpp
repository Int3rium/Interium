#include "packer.h"
#include <random>

namespace Packer {

std::vector<u8> a_JunkCode(const std::vector<u8>& data, size_t amount) {
    std::vector<u8> result;
    result.reserve(data.size() + amount);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    std::uniform_int_distribution<> posDis(0, data.size());
    
    result = data;
    
    for (size_t i = 0; i < amount; i++) {
        size_t pos = posDis(gen) % (result.size() + 1);
        result.insert(result.begin() + pos, static_cast<u8>(dis(gen)));
    }
    
    return result;
}

std::vector<u8> compress(const std::vector<u8>& data) {
    return data;
}

std::vector<u8> decompress(const std::vector<u8>& data) {
    return data;
}

} // namespace Packer

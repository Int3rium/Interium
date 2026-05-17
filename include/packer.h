#ifndef INTERIUM_PACKER_H
#define INTERIUM_PACKER_H

#include "types.h"
#include <vector>

namespace Packer {
    std::vector<u8> a_JunkCode(const std::vector<u8>& data, size_t amount);
    std::vector<u8> compress(const std::vector<u8>& data);
    std::vector<u8> decompress(const std::vector<u8>& data);
}

#endif

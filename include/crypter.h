#ifndef INTERIUM_CRYPTER_H
#define INTERIUM_CRYPTER_H

#include <string>
#include <vector>
#include "crypto.h"

class Crypter {
public:
    Crypter(const std::string& s_Path);

    bool l_Payload(const std::string& path);
    bool encrypt(Interium::ObfuscationLevel level, u8 flags);
    bool pack(const std::string& outputPath);

    size_t g_Size() const { return payload.size(); }

private:
    std::string s_Path;
    std::vector<u8> payload;
    std::vector<u8> e_Payload;
    std::vector<u8> key;
    Interium::ObfuscationLevel level;
    u8 flags;
};

#endif

#include "crypter.h"
#include "stub.h"
#include <fstream>
#include <iostream>

Crypter::Crypter(const std::string& s_Path) : s_Path(s_Path), level(Interium::ObfuscationLevel::MID), flags(0) {}

bool Crypter::l_Payload(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    payload.resize(size);
    file.read(reinterpret_cast<char*>(payload.data()), size);
    
    return file.good();
}

bool Crypter::encrypt(Interium::ObfuscationLevel lvl, u8 flg) {
    this->level = lvl;
    this->flags = flg;
    
    size_t keySize;
    switch (level) {
        case Interium::ObfuscationLevel::LOW:
            keySize = 16;
            break;
        case Interium::ObfuscationLevel::MID:
            keySize = 24;
            break;
        case Interium::ObfuscationLevel::HIGH:
            keySize = 32;
            break;
        default:
            keySize = 24;
    }
    
    key = Interium::Crypto::g_Key(keySize);
    e_Payload = Interium::Crypto::encrypt(payload, key, level);
    
    return !e_Payload.empty();
}

bool Crypter::pack(const std::string& outputPath) {
    // layout: [stub.exe] [StubConfig] [key] [encrypted payload]
    std::ifstream stubFile(s_Path, std::ios::binary | std::ios::ate);
    if (!stubFile.is_open()) {
        std::cerr << "Warning: Stub not found at " << s_Path << ", creating placeholder\n";
    }
    
    std::vector<u8> stubData;
    if (stubFile.is_open()) {
        size_t stubSize = stubFile.tellg();
        stubFile.seekg(0, std::ios::beg);
        stubData.resize(stubSize);
        stubFile.read(reinterpret_cast<char*>(stubData.data()), stubSize);
        stubFile.close();
    }
    
    StubConfig config;
    config.magic = STUB_MAGIC;
    config.payloadSize = e_Payload.size();
    config.keySize = key.size();
    config.level = static_cast<u8>(level);
    config.flags = flags;
    config.reserved[0] = 0;
    config.reserved[1] = 0;
    
    std::ofstream out(outputPath, std::ios::binary);
    if (!out.is_open()) return false;
    if (!stubData.empty()) {
        out.write(reinterpret_cast<char*>(stubData.data()), stubData.size());
    }
    
    out.write(reinterpret_cast<char*>(&config), sizeof(config));
    out.write(reinterpret_cast<char*>(key.data()), key.size());
    out.write(reinterpret_cast<char*>(e_Payload.data()), e_Payload.size());
    
    return out.good();
}

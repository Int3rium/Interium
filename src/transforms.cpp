#include "transforms.h"
#include <cstring>
#include <random>
#include <algorithm>

namespace Interium {

static std::mt19937& rng() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    return gen;
}

static u8 randByte() {
    return std::uniform_int_distribution<int>(0, 255)(rng());
}

void cleanRichHeader(PEFile& pe, Stats& stats) {
    auto& d = pe.data();
    auto* dos = pe.d_Header();
    size_t peOff = dos->e_lfanew;

    for (size_t i = 0x80; i + 4 <= peOff; i += 4) {
        if (*(u32*)(d.data() + i) == 0x68636952) {
            memset(&d[0x80], 0, peOff - 0x80);
            stats.metadataCleaned++;
            return;
        }
    }
}

void cleanMetadata(PEFile& pe, Stats& stats) {
    auto& d = pe.data();
    auto* fh = pe.f_Header();

    fh->TimeDateStamp = 0;
    fh->PointerToSymbolTable = 0;
    fh->NumberOfSymbols = 0;
    stats.metadataCleaned++;

    DATA_DIRECTORY* debugDir;
    if (pe.is64bit()) {
        debugDir = &pe.ntHeaders64()->OptionalHeader.DataDirectory[DIR_DEBUG];
    } else {
        debugDir = &pe.ntHeaders32()->OptionalHeader.DataDirectory[DIR_DEBUG];
    }

    if (debugDir->VirtualAddress && debugDir->Size) {
        u32 offset = pe.rvaToOffset(debugDir->VirtualAddress);
        if (offset && offset + debugDir->Size <= d.size()) {
            memset(&d[offset], 0, debugDir->Size);
        }
        debugDir->VirtualAddress = 0;
        debugDir->Size = 0;
        stats.metadataCleaned++;
    }
}

void killDosStub(PEFile& pe, Stats& stats) {
    auto& d = pe.data();
    auto* dos = pe.d_Header();

    static const u8 standardStub[] = { // ref: ai
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
        0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
        0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
        0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
        0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
        0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
        0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    size_t stubStart = 0x40;
    size_t stubEnd = std::min((size_t)dos->e_lfanew, d.size());

    if (stubEnd - stubStart >= sizeof(standardStub)) {
        memcpy(&d[stubStart], standardStub, sizeof(standardStub));
        for (size_t i = stubStart + sizeof(standardStub); i < stubEnd; i++) {
            d[i] = 0;
        }
        stats.metadataCleaned++;
    }
}

void spoofPECharacteristics(PEFile& pe, Stats& stats) {
    // most common linker version on VT right now
    if (pe.is64bit()) {
        auto* opt = &pe.ntHeaders64()->OptionalHeader;
        opt->MajorLinkerVersion = 14;
        opt->MinorLinkerVersion = 38;
        opt->MajorOperatingSystemVersion = 6;
        opt->MinorOperatingSystemVersion = 0;
        opt->MajorSubsystemVersion = 6;
        opt->MinorSubsystemVersion = 0;
        opt->MajorImageVersion = 0;
        opt->MinorImageVersion = 0;
        opt->Win32VersionValue = 0;
        opt->LoaderFlags = 0;
    } else {
        auto* opt = &pe.ntHeaders32()->OptionalHeader;
        opt->MajorLinkerVersion = 14;
        opt->MinorLinkerVersion = 38;
        opt->MajorOperatingSystemVersion = 6;
        opt->MinorOperatingSystemVersion = 0;
        opt->MajorSubsystemVersion = 6;
        opt->MinorSubsystemVersion = 0;
        opt->MajorImageVersion = 0;
        opt->MinorImageVersion = 0;
    }
    stats.metadataCleaned++;
}

void renameSections(PEFile& pe, Stats& stats) {
    auto* sections = pe.s_Headers();
    u16 count = pe.s_Count();

    // anything not in this list gets renamed to .data (UPX, VMProtect, Themida
    // all add custom section names that are trivial to sig on
    static const char* keep[] = {
        ".text", ".rdata", ".data", ".rsrc", ".reloc",
        ".pdata", ".bss", ".idata", ".CRT", ".tls", ".xdata"
    };

    for (u16 i = 0; i < count; i++) {
        char name[9] = {0};
        memcpy(name, sections[i].Name, 8);

        bool isStandard = false;
        for (const auto& k : keep) {
            if (strcmp(name, k) == 0) { isStandard = true; break; }
        }

        if (!isStandard && name[0] != 0) {
            memset(sections[i].Name, 0, 8);
            memcpy(sections[i].Name, ".data", 5);
            stats.sectionsRenamed++;
        }
    }
}

void shuffleImports(PEFile& pe, Stats& stats) {
    auto& d = pe.data();

    DATA_DIRECTORY* importDir;
    if (pe.is64bit()) {
        importDir = &pe.ntHeaders64()->OptionalHeader.DataDirectory[DIR_IMPORT];
    } else {
        importDir = &pe.ntHeaders32()->OptionalHeader.DataDirectory[DIR_IMPORT];
    }

    if (!importDir->VirtualAddress || !importDir->Size) return;

    u32 offset = pe.rvaToOffset(importDir->VirtualAddress);
    if (!offset) return;

    std::vector<IMPORT_DESCRIPTOR> descriptors;
    auto* imp = reinterpret_cast<IMPORT_DESCRIPTOR*>(&d[offset]);
    while (imp->Name) {
        descriptors.push_back(*imp);
        imp++;
    }

    if (descriptors.size() <= 1) return;
    std::shuffle(descriptors.begin(), descriptors.end(), rng());

    imp = reinterpret_cast<IMPORT_DESCRIPTOR*>(&d[offset]);
    for (size_t i = 0; i < descriptors.size(); i++) {
        imp[i] = descriptors[i];
    }
    stats.importsHidden += descriptors.size();
}

void addOverlay(PEFile& pe, Level level, Stats& stats) {
    auto& d = pe.data();

    u32 certLen = 2048;
    std::vector<u8> overlay(certLen, 0);

    u16 revision = 0x0200;
    u16 certType = 0x0002;
    memcpy(&overlay[0], &certLen, 4);
    memcpy(&overlay[4], &revision, 2);
    memcpy(&overlay[6], &certType, 2);

    u8 asn1[] = {
        0x30, 0x82, (u8)((certLen - 12) >> 8), (u8)((certLen - 12) & 0xFF),
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 // signedData
    };
    memcpy(&overlay[8], asn1, sizeof(asn1));

    for (size_t i = 8 + sizeof(asn1); i < overlay.size(); i++) {
        overlay[i] = randByte();
    }

    DATA_DIRECTORY* secDir;
    if (pe.is64bit()) {
        secDir = &pe.ntHeaders64()->OptionalHeader.DataDirectory[DIR_SECURITY];
    } else {
        secDir = &pe.ntHeaders32()->OptionalHeader.DataDirectory[DIR_SECURITY];
    }

    u32 overlayStart = d.size();
    secDir->VirtualAddress = overlayStart;
    secDir->Size = certLen;

    d.insert(d.end(), overlay.begin(), overlay.end());
    stats.junkBytesAdded += certLen;
}

void fixChecksum(PEFile& pe) {
    auto& d = pe.data();

    u32* checksumField;
    if (pe.is64bit())
        checksumField = &pe.ntHeaders64()->OptionalHeader.CheckSum;
    else
        checksumField = &pe.ntHeaders32()->OptionalHeader.CheckSum;

    u32 checksumOffset = (u32)(reinterpret_cast<u8*>(checksumField) - d.data());
    *checksumField = 0;

    u64 checksum = 0;
    for (size_t i = 0; i < d.size(); i += 2) {
        if (i == checksumOffset) continue;
        u16 val;
        if (i + 1 < d.size())
            val = *(u16*)&d[i];
        else
            val = d[i];
        checksum += val;
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum += d.size();

    *checksumField = (u32)checksum;
}

}

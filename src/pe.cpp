#include "pe.h"
#include <fstream>
#include <cstring>
#include <algorithm>

namespace Interium {

bool PEFile::load(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;

    size_t size = file.tellg();
    file.seekg(0);
    raw.resize(size);
    file.read(reinterpret_cast<char*>(raw.data()), size);
    if (!file.good()) return false;

    if (size < sizeof(DOS_HEADER)) return false;
    auto* dos = d_Header();
    if (dos->e_magic != 0x5A4D) return false;

    if ((size_t)dos->e_lfanew + 4 + sizeof(FILE_HEADER) > size) return false;
    u32 sig = *(u32*)(raw.data() + dos->e_lfanew);
    if (sig != 0x00004550) return false;

    auto* fh = f_Header();
    u16 magic = *(u16*)(raw.data() + dos->e_lfanew + 4 + sizeof(FILE_HEADER));
    is64 = (magic == 0x020B);

    return true;
}

bool PEFile::save(const std::string& path) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(reinterpret_cast<char*>(raw.data()), raw.size());
    return file.good();
}

DOS_HEADER* PEFile::d_Header() {
    return reinterpret_cast<DOS_HEADER*>(raw.data());
}

NT_HEADERS_64* PEFile::ntHeaders64() {
    return reinterpret_cast<NT_HEADERS_64*>(raw.data() + d_Header()->e_lfanew);
}

NT_HEADERS_32* PEFile::ntHeaders32() {
    return reinterpret_cast<NT_HEADERS_32*>(raw.data() + d_Header()->e_lfanew);
}

FILE_HEADER* PEFile::f_Header() {
    return reinterpret_cast<FILE_HEADER*>(raw.data() + d_Header()->e_lfanew + 4);
}

SECTION_HEADER* PEFile::s_Headers() {
    auto* fh = f_Header();
    u8* afterOptional = raw.data() + d_Header()->e_lfanew + 4 + sizeof(FILE_HEADER) + fh->SizeOfOptionalHeader;
    return reinterpret_cast<SECTION_HEADER*>(afterOptional);
}

u16 PEFile::s_Count() const {
    auto* fh = const_cast<PEFile*>(this)->f_Header();
    return fh->NumberOfSections;
}

u32 PEFile::entryPoint() const {
    if (is64) {
        return const_cast<PEFile*>(this)->ntHeaders64()->OptionalHeader.AddressOfEntryPoint;
    }
    return const_cast<PEFile*>(this)->ntHeaders32()->OptionalHeader.AddressOfEntryPoint;
}

SECTION_HEADER* PEFile::findSection(const std::string& name) {
    auto* sections = s_Headers();
    for (u16 i = 0; i < s_Count(); i++) {
        char secName[9] = {0};
        memcpy(secName, sections[i].Name, 8);
        if (name == secName) return &sections[i];
    }
    return nullptr;
}

SECTION_HEADER* PEFile::sectionFromRva(u32 rva) {
    auto* sections = s_Headers();
    for (u16 i = 0; i < s_Count(); i++) {
        u32 start = sections[i].VirtualAddress;
        u32 end = start + sections[i].VirtualSize;
        if (rva >= start && rva < end) return &sections[i];
    }
    return nullptr;
}

u32 PEFile::rvaToOffset(u32 rva) {
    auto* sec = sectionFromRva(rva);
    if (!sec) return 0;
    return rva - sec->VirtualAddress + sec->PointerToRawData;
}

u32 PEFile::offsetToRva(u32 offset) {
    auto* sections = s_Headers();
    for (u16 i = 0; i < s_Count(); i++) {
        u32 start = sections[i].PointerToRawData;
        u32 end = start + sections[i].SizeOfRawData;
        if (offset >= start && offset < end) {
            return offset - start + sections[i].VirtualAddress;
        }
    }
    return 0;
}

bool PEFile::hasRichHeader() const {
    auto* d = const_cast<PEFile*>(this)->d_Header();
    size_t searchEnd = std::min((size_t)d->e_lfanew, raw.size());
    //0x80
    for (size_t i = 0x80; i + 4 <= searchEnd; i += 4) {
        if (*(u32*)(raw.data() + i) == 0x68636952)
            return true;
    }
    return false;
}

size_t PEFile::richHeaderOffset() const {
    auto* d = const_cast<PEFile*>(this)->d_Header();
    return 0x80;
}

size_t PEFile::richHeaderSize() const {
    auto* d = const_cast<PEFile*>(this)->d_Header();
    size_t searchEnd = std::min((size_t)d->e_lfanew, raw.size());
    for (size_t i = 0x80; i + 4 <= searchEnd; i += 4) {
        if (*(u32*)(raw.data() + i) == 0x68636952) {
            return (i + 8) - 0x80; // +8
        }
    }
    return 0;
}

SECTION_HEADER* PEFile::addSection(const std::string& name, u32 size, u32 characteristics) {
    auto* fh = f_Header();
    auto* sections = s_Headers();
    u16 numSec = fh->NumberOfSections;
    auto& lastSec = sections[numSec - 1];

    u32 fileAlign, sectionAlign;
    if (is64) {
        fileAlign = ntHeaders64()->OptionalHeader.FileAlignment;
        sectionAlign = ntHeaders64()->OptionalHeader.SectionAlignment;
    } else {
        fileAlign = ntHeaders32()->OptionalHeader.FileAlignment;
        sectionAlign = ntHeaders32()->OptionalHeader.SectionAlignment;
    }

    auto align = [](u32 val, u32 a) -> u32 {
        return (val + a - 1) & ~(a - 1);
    };

    u32 newRawOffset = align(lastSec.PointerToRawData + lastSec.SizeOfRawData, fileAlign);
    u32 newRawSize = align(size, fileAlign);
    u32 newVA = align(lastSec.VirtualAddress + lastSec.VirtualSize, sectionAlign);
    u32 newVirtualSize = align(size, sectionAlign);

    u8* newSecPtr = reinterpret_cast<u8*>(&sections[numSec]);
    size_t headerEnd = newSecPtr - raw.data() + sizeof(SECTION_HEADER);
    u32 headersSize = is64 ? ntHeaders64()->OptionalHeader.SizeOfHeaders : ntHeaders32()->OptionalHeader.SizeOfHeaders;
    if (headerEnd > headersSize) return nullptr;

    raw.resize(newRawOffset + newRawSize, 0);

    fh = f_Header();
    sections = s_Headers();

    auto* newSec = &sections[numSec];
    memset(newSec, 0, sizeof(SECTION_HEADER));
    memcpy(newSec->Name, name.c_str(), std::min(name.size(), (size_t)8));
    newSec->VirtualSize = size;
    newSec->VirtualAddress = newVA;
    newSec->SizeOfRawData = newRawSize;
    newSec->PointerToRawData = newRawOffset;
    newSec->Characteristics = characteristics;

    fh->NumberOfSections = numSec + 1;

    if (is64) {
        ntHeaders64()->OptionalHeader.SizeOfImage = align(newVA + newVirtualSize, sectionAlign);
    } else {
        ntHeaders32()->OptionalHeader.SizeOfImage = align(newVA + newVirtualSize, sectionAlign);
    }

    return newSec;
}

} // namespace Interium
